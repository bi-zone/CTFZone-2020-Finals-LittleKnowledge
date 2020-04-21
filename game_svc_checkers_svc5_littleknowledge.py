# -*- coding: utf-8 -*-
import logging
from redis import StrictRedis
from game_svc.utils.other import get_redis_statuses_unique_key
from game_svc.config.game_settings import SERVICE_STATE_UP, SERVICE_STATE_DOWN, SERVICE_STATE_MUMBLE, \
    SERVICE_STATE_CORRUPTED
from datetime import datetime
from zkn_checker import *
SERVICE_ID = 5
logger = logging.getLogger('checkers')
logger.propagate = False

CHALLENGE_PORT=666
def svc5_checker(team_id, ip, flag, redis_conf):
    redis_conn = StrictRedis(**redis_conf, charset="utf-8", decode_responses=True)

    # getting state from last run
    state_key = get_redis_statuses_unique_key(team_id=team_id, service_id=SERVICE_ID)
    state = redis_conn.hgetall(state_key)

    last_flag = state.get("last_flag")
    flag_pushed = state.get("flag_pushed") == 'True'
    status = state.get("status")
    email = state.get("email")
    password = state.get("password")
    stored_full_knowledge=state.get("stored_full_knowledge")
    # PUSH if flag is new (new round) or we didn't pushed in last try
    if last_flag != flag or not flag_pushed:
        (push_status,sfkn)=push_flag(ip,CHALLENGE_PORT,flag)
        # push flag
        if push_status==SUCCESS:
            flag_pushed=True
            stored_full_knowledge=sfkn
        else:
            flag_pushed=False
        if flag_pushed:
            trace = "Everything fine"
            status = SERVICE_STATE_UP
            flag_pushed = True
        else:
            trace = "Exception in push"
            status = SERVICE_STATE_CORRUPTED
            flag_pushed = False

    # try pull if flag is pushed
    if flag_pushed:
        # pull flag
        pull_status=pull_flag(ip,CHALLENGE_PORT,flag)
        flag_pulled = pull_status==SUCCESS
        if flag_pulled:
            trace = "Everything fine"
            status = SERVICE_STATE_UP
        else:
            trace = "Exception in pull"
            status = SERVICE_STATE_MUMBLE

    # if flag is pushed and pulled
    if status == SERVICE_STATE_UP:
        # check other stuff
        service_is_correct = True
        if service_is_correct:
            trace = "Everything fine"
            status = SERVICE_STATE_UP
        else:
            trace = "Exception in logic"
            status = SERVICE_STATE_MUMBLE

    # state for checker, write whatever you need. No strict format
    service_status = {'date': datetime.now().isoformat(),
                      'last_flag': flag,
                      'flag_pushed': flag_pushed,
                      'email': email,
                      'password': password,
                      'stored_full_knowledge':stored_full_knowledge}

    # saving full state
    redis_conn.hmset(state_key, service_status)

    # state for scoreboard, strict properties
    redis_conn.hset(state_key, 'status', status)
    redis_conn.hset(state_key, 'trace', trace)

    # return status for SLA calculation
    return status
