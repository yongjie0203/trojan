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

#ifndef _AUTHENTICATOR_H_
#define _AUTHENTICATOR_H_

#ifdef ENABLE_MYSQL
#include <mysql.h>
#include <ctime>
#endif // ENABLE_MYSQL
#include "config.h"

class Authenticator {
private:
#ifdef ENABLE_MYSQL
    MYSQL con;
#endif // ENABLE_MYSQL
    Config conf;
    enum {
        PASSWORD_LENGTH=56
    };
    bool is_valid_password(const std::string &password);
public:
    Authenticator(const Config &config);
    bool auth(const std::string &password);
    void record(const std::string &password, uint64_t download, uint64_t upload);
    
    ~Authenticator();
#ifdef ENABLE_MYSQL
    std::string traffic_format(uint64_t traffic);
    void cleanUserInfo(const std::string &password);
    class TrafficInfoCache{
        public:
            time_t last_time;//上次记录时间
            uint64_t download;
            uint64_t upload;
            int skip;
            uint64_t user_id;
            std::string user_name;
    } ;
    extern  std::map<std::string, Authenticator::TrafficInfoCache> trafficInfoMap;
  #endif // ENABLE_MYSQL  
};

#endif // _AUTHENTICATOR_H_
