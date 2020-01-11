/*
 * This file is part of the trojan project.
 * Trojan is an unidentifiable mechanism that helps you bypass GFW.
 * Copyright (C) 2017-2019  GreaterFire, wongsyrone
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "authenticator.h"
#include <cstdlib>
#include <stdexcept>
#include <ctime>
#include <iomanip>
using namespace std;

#ifdef ENABLE_MYSQL

Authenticator::Authenticator(const Config &config) {
    conf = config;
    mysql_init(&con);
    Log::log_with_date_time("connecting to MySQL server " + config.mysql.server_addr + ':' + to_string(config.mysql.server_port), Log::INFO);
    if (mysql_real_connect(&con, config.mysql.server_addr.c_str(),
                                 config.mysql.username.c_str(),
                                 config.mysql.password.c_str(),
                                 config.mysql.database.c_str(),
                                 config.mysql.server_port, NULL, 0) == NULL) {
        throw runtime_error(mysql_error(&con));
    }
    bool reconnect = 1;
    mysql_options(&con, MYSQL_OPT_RECONNECT, &reconnect);
    Log::log_with_date_time("connected to MySQL server", Log::INFO);
}

bool Authenticator::auth(const string &password) {
    /*Log::log_with_date_time("debug:user " + password + " connected", Log::INFO);*/
    if (!is_valid_password(password)) {
        return false;
    }
    if (mysql_query(&con, ("SELECT transfer_enable, d + u FROM `user` WHERE sha2(trojan_password,224) = '" + password + '\'').c_str())) {
        Log::log_with_date_time(mysql_error(&con), Log::ERROR);
        return false;
    }
    MYSQL_RES *res = mysql_store_result(&con);
    if (res == NULL) {
        Log::log_with_date_time(mysql_error(&con), Log::ERROR);
        return false;
    }
    MYSQL_ROW row = mysql_fetch_row(res);
    if (row == NULL) {
        mysql_free_result(res);
        return false;
    }
    int64_t quota = atoll(row[0]);
    int64_t used = atoll(row[1]);
    mysql_free_result(res);
    if (quota < 0) {
        return true;
    }
    if (used >= quota) {
        Log::log_with_date_time(password + " ran out of quota", Log::WARN);
        return false;
    }
    return true;
}

void Authenticator::record(const std::string &password, uint64_t download, uint64_t upload) {
    static std::map<std::string, Authenticator::TrafficInfoCache> trafficInfoMap;
    Log::log_with_date_time("debug:user " + password + " record update , down:" + to_string(download) +" up:" + to_string(upload)  , Log::INFO);
    if (!is_valid_password(password)) {
        return;
    }
    if (mysql_query(&con, ("UPDATE user SET d = d + " + to_string(download) + ", u = u + " + to_string(upload) + " WHERE sha2(trojan_password,224) = '" + password + '\'').c_str())) {
        Log::log_with_date_time(mysql_error(&con), Log::ERROR);
    }    
    if( trafficInfoMap.find(password) != trafficInfoMap.end()){//有缓存记录，本次也跳过的情况
        TrafficInfoCache trafficInfo = trafficInfoMap[password];
        Log::log_with_date_time("debug:user " + password + " [download:"+ to_string(trafficInfo.download) +", upload:"+ to_string(trafficInfo.upload) +", last_time:"+ to_string(trafficInfo.last_time) +", skip:"+ to_string(trafficInfo.skip) +"]"  , Log::INFO);        
        if(trafficInfo.download + trafficInfo.upload + download + upload < (uint64_t)(1024 * (2048 - trafficInfo.skip * 64)) ){
            trafficInfo.skip = trafficInfo.skip + 1;
            trafficInfo.download = trafficInfo.download + download;
            trafficInfo.upload = trafficInfo.upload + upload;            
            trafficInfoMap[password] = trafficInfo;
            return;
        }
        if(difftime(time(0),trafficInfo.last_time) < 60 ){
            trafficInfo.skip = trafficInfo.skip + 1;
            trafficInfo.download = trafficInfo.download + download;
            trafficInfo.upload = trafficInfo.upload + upload;  
            trafficInfoMap[password] = trafficInfo;
            return;
        }
        //上报流量记录处理        
        if (mysql_query(&con, ("insert into  user_traffic_log (`user_id`, `u`, `d`, `node_id`, `rate`, `traffic`, `log_time`) VALUES (1,"+ to_string(trafficInfo.upload*conf.rate) +","+ to_string(trafficInfo.download * conf.rate) +","+to_string(conf.server_id) +" , "+ to_string(conf.rate) +", "+ to_string(Authenticator::traffic_format((uint64_t)((trafficInfo.download+trafficInfo.upload)*conf.rate))) +",unix_timestamp() )").c_str())) {
            Log::log_with_date_time(mysql_error(&con), Log::ERROR);
        }
        //更新缓存
        trafficInfoMap.erase(password);
    }else{//无缓存记录
        if(download + upload < 1024 * (2048 - 0 * 64) ){
            TrafficInfoCache trafficInfo ;
            trafficInfo.download = download;
            trafficInfo.upload = upload;
            trafficInfo.last_time = time(0);
            trafficInfo.skip = 1;
            trafficInfoMap[password] = trafficInfo;
        }else{
            //上报流量记录处理             
            if (mysql_query(&con, ("insert into  user_traffic_log (`user_id`, `u`, `d`, `node_id`, `rate`, `traffic`, `log_time`) VALUES (1,"+ to_string(upload * conf.rate) +","+ to_string(download * conf.rate) +","+to_string(conf.server_id) +" , "+ to_string(conf.rate) +", "+ to_string(Authenticator::traffic_format((uint64_t)((download+upload)*conf.rate))) +",unix_timestamp() )").c_str())) {
                Log::log_with_date_time(mysql_error(&con), Log::ERROR);
            }
        }       
        
    }
    
    
}

bool Authenticator::is_valid_password(const std::string &password) {
    if (password.size() != PASSWORD_LENGTH) {
        return false;
    }
    for (size_t i = 0; i < PASSWORD_LENGTH; ++i) {
        if (!((password[i] >= '0' && password[i] <= '9') || (password[i] >= 'a' && password[i] <= 'f'))) {
            return false;
        }
    }
    return true;
}

static string Authenticator::traffic_format(uint64_t traffic) { 
    if (traffic < 1024 * 8){
        return to_string(traffic) + "B";
    }     
    if (traffic < 1024 * 1024 * 2){
        return to_string( setiosflags(ios::fixed)<<setprecision(2)<< (traffic/ 1024.0)) + "KB";
    }           
    return to_string(setiosflags(ios::fixed)<<setprecision(2)<< (traffic / 1048576.0) ) + "MB";
}

Authenticator::~Authenticator() {
    mysql_close(&con);
}

#else // ENABLE_MYSQL

Authenticator::Authenticator(const Config&) {}
bool Authenticator::auth(const string&) { return true; }
void Authenticator::record(const std::string&, uint64_t, uint64_t) {}
bool Authenticator::is_valid_password(const std::string&) { return true; }
static std::string Authenticator::traffic_format(uint64_t traffic) { return null; }
Authenticator::~Authenticator() {}

#endif // ENABLE_MYSQL
