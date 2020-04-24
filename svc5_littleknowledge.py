# -*- coding: utf-8 -*-
import logging
from redis import StrictRedis
from game_svc.utils.other import get_redis_statuses_unique_key
from game_svc.config.game_settings import SERVICE_STATE_UP, SERVICE_STATE_DOWN, SERVICE_STATE_MUMBLE, \
    SERVICE_STATE_CORRUPTED
from datetime import datetime
from .zkn_checker import *
SERVICE_ID = 5
logger = logging.getLogger('checkers')
logger.propagate = False

CHALLENGE_PORT=666
def message(team_id,action,result):
    return repr(action)+' for team: '+repr(team_id) +', resulted in: '+repr(result)
def message_for_team(action,result):
    return str(result)+' '+str(action)
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
    if stored_full_knowledge!=None:
        try:
            stored_full_knowledge=bytes.fromhex(stored_full_knowledge)
        except ValueError:
            stored_full_knowledge=None
    # PUSH if flag is new (new round) or we didn't pushed in last try
    pushing_now=False
    trace=':('
    if last_flag != flag or not flag_pushed:
        pushing_now=True
        try:
            completedFunction=False
            (push_status,sfkn)=push_flag(ip,CHALLENGE_PORT,flag)
            completedFunction=True
        except Exception:
            flag_pushed=False
            status=SERVICE_STATE_MUMBLE
            logger.info(message(team_id,'PUSH','GENERAL EXCEPTION'))
            trace=message_for_team('PUSH','GENERAL EXCEPTION') 
        if completedFunction:
            if is_success_return_code(push_status):
                flag_pushed=True
                stored_full_knowledge=sfkn
            else:
                flag_pushed=False
            # push flag
            if push_status==SUCCESS:
                flag_pushed=True
                stored_full_knowledge=sfkn
                status=SERVICE_STATE_UP
            else:
                flag_pushed=False
                if is_down_return_code(push_status):
                    status=SERVICE_STATE_DOWN
                elif is_corrupt_return_code(push_status):
                    status=SERVICE_STATE_CORRUPTED
                elif is_mumble_return_code(push_status):
                    status=SERVICE_STATE_MUMBLE
                else:
                    status=SERVICE_STATE_MUMBLE
                    logger.info(message(team_id,'PUSH','STATE THAT CAN\'T HAPPEN'))
            trace=message_for_team('PUSH',error_disambiguation(push_status))
            logger.info(message(team_id,'PUSH',error_disambiguation(push_status)))
    # try pull if flag is pushed
    if flag_pushed:
        # pull flag
        try:
            completedFunction=False
            if pushing_now:
                pull_status=pull_flag(ip,CHALLENGE_PORT,flag,stored_full_knowledge)
            else:
                pull_status=complex_pull_flag(ip,CHALLENGE_PORT,flag,stored_full_knowledge)
            completedFunction=True
        except Exception:
            flag_pulled=False
            status=SERVICE_STATE_MUMBLE
            logger.info(message(team_id,'PULL','GENERAL EXCEPTION'))
            trace=message_for_team('PULL','GENERAL EXCEPTION')
        if completedFunction:
            if is_success_return_code(pull_status):
                status=SERVICE_STATE_UP
            elif is_down_return_code(pull_status):
                status=SERVICE_STATE_DOWN
            elif is_corrupt_return_code(pull_status):
                status=SERVICE_STATE_CORRUPTED
            elif is_mumble_return_code(pull_flag):
                status=SERVICE_STATE_MUMBLE
            else:
                status=SERVICE_STATE_MUMBLE
                logger.info(message(team_id,'PULL','STATE THAT CAN\'T HAPPEN'))
            trace=message_for_team('PULL',error_disambiguation(pull_status))
            logger.info(message(team_id,'PULL',error_disambiguation(pull_status)))


    # state for checker, write whatever you need. No strict format
    if stored_full_knowledge!=None:
        service_status = {'date': datetime.now().isoformat(),
                      'last_flag': flag,
                      'flag_pushed': flag_pushed,
                      'email': email,
                      'password': password,
                      'stored_full_knowledge':stored_full_knowledge.hex()}
    else:
        service_status = {'date': datetime.now().isoformat(),
                      'last_flag': flag,
                      'flag_pushed': flag_pushed,
                      'email': email,
                      'password': password}


    # saving full state
    redis_conn.hmset(state_key, service_status)

    # state for scoreboard, strict properties
    redis_conn.hset(state_key, 'status', status)
    redis_conn.hset(state_key, 'trace', trace)

    # return status for SLA calculation
    return status
