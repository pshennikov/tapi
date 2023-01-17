#!flask/bin/python
# coding=utf-8

__author__ = "Leonid Pshennikov"


import re
import ESL
import random
import shutil
import logging
import MySQLdb
import hashlib
import json

from tapi_config import *
from tapi_function import *
from datetime import datetime

from flask import Flask, jsonify
from flask import abort
from flask import make_response
from flask import render_template, request


logging.basicConfig(filename=log_path, level=logging.INFO)

app = Flask(__name__)


@app.route('/tapi/v1.0/originate', methods=['POST'])
def originate():
    if not request.json:
        return jsonify({'status': "nok"}), 400

    if not request.json or not 'caller_id' in request.json:
        abort(400)

    if not request.json or not 'did' in request.json:
        abort(400)

    if not request.json or not 'dial_timeout' in request.json:
        abort(400)

    if not request.json or not 'duration_limit' in request.json:
        abort(400)

    if not request.json or not 'call_id' in request.json:
        abort(400)

    if not request.json or not 'logic_id' in request.json:
        abort(400)

    if not request.json or not 'role' in request.json:
        abort(400)

    caller_id = request.json['caller_id']
    did = request.json['did']
    bnum = did
    anum = caller_id
    clid = request.json['clid']
    call_id = request.json['call_id']
    callback_id = request.json['callback_id']
    dial_timeout = request.json['dial_timeout']
    duration_limit = request.json['duration_limit']
    logic_id = request.json['logic_id']
    role = request.json['role']
    # is_premedia = request.json['is_premedia']
    is_premedia = False
    diversion_number = request.json['diversion_number']

    if not 'trunk_id' in request.json or request.json['trunk_id'] == "-1" or request.json['trunk_id'] == "0":
        trunk_id = None
    else:
        trunk_id = request.json['trunk_id']

    if not 'operator_trunk_id' in request.json or request.json['operator_trunk_id'] != 11:
        operator_trunk_id = None
    else:
        operator_trunk_id = request.json['operator_trunk_id']

    # origination_uuid = random.randint(1, 4294967296)
    m = hashlib.md5()
    m.update(now())
    mdate = m.hexdigest()
    origination_uuid = str(mdate) + "-" + str(random.randint(1, 4294967296))

    unique_id = random.randint(1, 4294967296)

    logging.info("lpt_callback | {} | {} | origination_uuid: {}".format(
        now(), str(unique_id), origination_uuid)
    )

    logging.info("lpt_callback | {} | {} | request_json: {}".format(
        now(), str(unique_id), request.data)
    )

    logging.info("lpt_callback | {} | {} | caller_id={} did={} clid={} call_id={} callback_id={}".format(
        now(), str(unique_id), caller_id, did, clid, call_id, callback_id)
    )
    logging.info("lpt_callback | {} | {} | dial_timeout={} duration_limit={} logic_id={} role={}".format(
        now(), str(unique_id), dial_timeout, duration_limit, logic_id, role)
    )
    logging.info("lpt_callback | {} | {} | trunk_id={}".format(
        now(), str(unique_id),  str(trunk_id))
    )
    logging.info("lpt_callback | {} | {} | operator_trunk_id={}".format(
        now(), str(unique_id),  str(operator_trunk_id))
    )
    logging.info("lpt_callback | {} | {} | is_premedia: {}".format(
        now(), str(unique_id),  str(is_premedia))
    )


    if trunk_id:
        if is_premedia:
            originate_cmd = 'originate {diversion_number=' + str(diversion_number) + ',is_premedia=' + str(is_premedia) + ',clid=' + str(clid) + ',operator_trunk_id=' + str(operator_trunk_id) + ',trunk_id=' + str(trunk_id) + ',logic_id=' + str(logic_id) + ',role=' + str(
                role) + ',originate_timeout=' + str(dial_timeout) + ',origination_uuid=' + str(
                origination_uuid) + ',origination_caller_id_number=' + str(anum) + ',unique_id=' + str(
                unique_id) + ',callback_id=' + str(callback_id) + ',dial_timeout=' + str(
                dial_timeout) + ',duration_limit=' + str(duration_limit) + '}loopback/client_trunk_callback-leg-a_0' + str(
                bnum) + '/public callback-leg-b_' + str(bnum) + ' xml public'
        else:
            originate_cmd = 'originate {diversion_number=' + str(diversion_number) + ',is_premedia=' + str(is_premedia) + ',clid=' + str(clid) + ',operator_trunk_id=' + str(operator_trunk_id) + ',trunk_id=' + str(trunk_id) + ',logic_id=' + str(logic_id) + ',role=' + str(
                role) + ',originate_timeout=' + str(dial_timeout) + ',origination_uuid=' + str(
                origination_uuid) + ',ignore_early_media=true,origination_caller_id_number=' + str(anum) + ',unique_id=' + str(
                unique_id) + ',callback_id=' + str(callback_id) + ',dial_timeout=' + str(
                dial_timeout) + ',duration_limit=' + str(duration_limit) + '}loopback/client_trunk_callback-leg-a_0' + str(
                bnum) + '/public callback-leg-b_' + str(bnum) + ' xml public'
    else:
        if is_premedia:
            originate_cmd = 'originate {diversion_number=' + str(diversion_number) + ',is_premedia=' + str(is_premedia) + ',clid=' + str(clid) + ',operator_trunk_id=' + str(operator_trunk_id) + ',logic_id=' + str(logic_id) + ',role=' + str(role) + ',originate_timeout=' + str(
                dial_timeout) + ',origination_uuid=' + str(
                origination_uuid) + ',origination_caller_id_number=' + str(anum) + ',unique_id=' + str(
                unique_id) + ',callback_id=' + str(callback_id) + ',dial_timeout=' + str(
                dial_timeout) + ',duration_limit=' + str(duration_limit) + '}loopback/callback-leg-a_0' + str(
                bnum) + '/public callback-leg-b_' + str(bnum) + ' xml public'
        else:
            originate_cmd = 'originate {diversion_number=' + str(diversion_number) + ',is_premedia=' + str(is_premedia) + ',clid=' + str(clid) + ',operator_trunk_id=' + str(operator_trunk_id) + ',logic_id=' + str(logic_id) + ',role=' + str(role) + ',originate_timeout=' + str(
                dial_timeout) + ',origination_uuid=' + str(
                origination_uuid) + ',ignore_early_media=true,origination_caller_id_number=' + str(anum) + ',unique_id=' + str(
                unique_id) + ',callback_id=' + str(callback_id) + ',dial_timeout=' + str(
                dial_timeout) + ',duration_limit=' + str(duration_limit) + '}loopback/callback-leg-a_0' + str(
                bnum) + '/public callback-leg-b_' + str(bnum) + ' xml public'

#    if trunk_id:
#        originate_cmd = 'originate {trunk_id=' + str(trunk_id) + ',logic_id=' + str(logic_id) + ',role=' + str(
#            role) + ',originate_timeout=' + str(dial_timeout) + ',origination_uuid=' + str(
#            origination_uuid) + ',origination_caller_id_number=' + str(anum) + ',unique_id=' + str(
#            unique_id) + ',callback_id=' + str(callback_id) + ',dial_timeout=' + str(
#            dial_timeout) + ',duration_limit=' + str(duration_limit) + '}loopback/client_trunk_callback-leg-a_0' + str(
#            bnum) + '/public callback-leg-b_' + str(bnum) + ' xml public'
#    else:
#        originate_cmd = 'originate {logic_id=' + str(logic_id) + ',role=' + str(role) + ',originate_timeout=' + str(
#            dial_timeout) + ',origination_uuid=' + str(
#            origination_uuid) + ',origination_caller_id_number=' + str(anum) + ',unique_id=' + str(
#            unique_id) + ',callback_id=' + str(callback_id) + ',dial_timeout=' + str(
#            dial_timeout) + ',duration_limit=' + str(duration_limit) + '}loopback/callback-leg-a_0' + str(
#            bnum) + '/public callback-leg-b_' + str(bnum) + ' xml public'

    logging.info("lpt_callback | {} | {} | originate_cmd={}".format(
        now(), str(unique_id), originate_cmd)
    )

    node_ip = None
    flag_already_processed_that_clid = 0
    is_enabled_autofunnel_logic = True

    if clid:
        flag_already_processed_that_clid = check_exist_clid_in_key_member(clid)

        if flag_already_processed_that_clid == 1:
            node_ip = get_node_ip_from_pair_clid_node_ip(clid)
            if node_ip is None or node_ip == "None":
                pass
            else:
                is_enabled_autofunnel_logic = False
            logging.info("lpt_callback | {} | {} | get_node_ip_from_pair_clid_node_ip | that call for node_ip={}".format(
                now(), str(unique_id), node_ip)
            )
        else:
            node_ip = get_node_ip_from_clid(clid, nodes)
            if node_ip is None or node_ip == "None":
                pass
            else:
                is_enabled_autofunnel_logic = False
            logging.info("lpt_callback | {} | {} | get_node_ip_from_clid | that call for node_ip={}".format(
                now(), str(unique_id), node_ip)
            )

    if (node_ip is None or node_ip == "None") and call_id:
        node_ip = get_node_ip_from_call_id_redis(call_id, nodes)
        if node_ip is None or node_ip == "None":
            pass
        else:
            is_enabled_autofunnel_logic = False
        logging.info("lpt_callback | {} | {} | get_node_ip_from_call_id_redis | that call for node_ip={}".format(
            now(), str(unique_id), node_ip)
        )

        # balancer:
        if node_ip is None or node_ip == "None":
            esl_calls_count_string_node_1 = (execute_esl_command_slowly('show calls count', '31.131.249.26'))
            esl_calls_count_node_1 = int(esl_calls_count_string_node_1.split()[0])

            esl_calls_count_string_node_2 = (execute_esl_command_slowly('show calls count', '31.131.249.29'))
            esl_calls_count_node_2 = int(esl_calls_count_string_node_2.split()[0])

            logging.info("lpt_callback | {} | {} | esl_calls_count_node_1={}, esl_calls_count_node_2={}".format(
                now(), str(unique_id), esl_calls_count_node_1, esl_calls_count_node_2)
            )

            if esl_calls_count_node_1 == -1 and esl_calls_count_node_2 >= 0:
                # node_ip = redis_host_cl_2
                node_ip = nodes.get('fs-2')
                redis_ip = redis_host_cl_2

            elif esl_calls_count_node_2 == -1 and esl_calls_count_node_1 >= 0:
                # node_ip = redis_host_cl_1
                node_ip = nodes.get('fs-1')
                redis_ip = redis_host_cl_1

            elif esl_calls_count_node_1 >= 0 and esl_calls_count_node_1 <= esl_calls_count_node_2:
                # node_ip = redis_host_cl_1
                node_ip = nodes.get('fs-1')
                redis_ip = redis_host_cl_1

            elif esl_calls_count_node_2 >= 0 and esl_calls_count_node_2 <= esl_calls_count_node_1:
                # node_ip = redis_host_cl_2
                node_ip = nodes.get('fs-2')
                redis_ip = redis_host_cl_2

            if balancer_enable != 1:
                # node_ip = redis_host_cl_1
                node_ip = nodes.get('fs-1')
                redis_ip = redis_host_cl_1

            # if node_ip is None:
            #     node_ip = redis_host_cl_1

             # if node_ip is None:
            #     random_bit = random.getrandbits(1)
            #     if bool(random_bit):
            #         node_ip = redis_host_cl_2
            #     else:
            #         node_ip = redis_host_cl_1

            logging.info("lpt_callback | {} | {} | balancer | that call for node_ip={}".format(
                now(), str(unique_id), node_ip)
            )

    # if node_ip is None or node_ip == "None":
    #     node_ip = redis_host_cl_1

    if node_ip is None or node_ip == "None":
        random_bit = random.getrandbits(1)
        if bool(random_bit):
            # node_ip = redis_host_cl_2
            node_ip = nodes.get('fs-2')
            redis_ip = redis_host_cl_2

        else:
            # node_ip = redis_host_cl_1
            node_ip = nodes.get('fs-1')
            redis_ip = redis_host_cl_1

    call_case = clid.split('-')[1]
    logging.info("lpt_callback | {} | {} | call_case={}".format(
        now(), str(unique_id), call_case)
    )

    if re.search(r'autofunnel', call_case) and is_enabled_autofunnel_logic:
        logging.info("lpt_callback | {} | {} | that call is autofunnel".format(
            now(), str(unique_id))
        )
        # # node_ip = redis_host_cl_3
        # node_ip = nodes.get('fs-3')
        # redis_ip = redis_host_cl_3

        random_bet = random.getrandbits(1)
        if bool(random_bet):
            node_ip = nodes.get('fs-3')
            redis_ip = redis_host_cl_3

        else:
            node_ip = nodes.get('fs-4')
            redis_ip = redis_host_cl_4

    if flag_already_processed_that_clid == 0:
        execute_redis_command('SET', "pair_clid_node_ip-"+clid, node_ip, host=redis_host, port=redis_port, db=redis_db)
        execute_redis_command('SADD', "clid_key_member", clid, host=redis_host, port=redis_port, db=redis_db)

    execute_esl_command(originate_cmd, node_ip)

    logging.info("lpt_callback | {} | {} | originate sent cmd={}, node_ip={}".format(
        now(), str(unique_id), originate_cmd, node_ip)
    )

    return jsonify(
        {
            "status_code": "1",
            "status_info": "ok"
        }
    ), 200


@app.route('/tapi/v1.0/local', methods=['POST'])
def originate_local():
    if not request.json:
        return jsonify({'status': "nok"}), 400

    if not request.json or not 'caller_id' in request.json:
        abort(400)

    if not request.json or not 'did' in request.json:
        abort(400)

    if not request.json or not 'dial_timeout' in request.json:
        abort(400)

    if not request.json or not 'duration_limit' in request.json:
        abort(400)

    if not request.json or not 'call_id' in request.json:
        abort(400)

    caller_id = request.json['caller_id']
    did = request.json['did']
    bnum = did
    anum = caller_id
    clid = request.json['clid']
    call_id = request.json['call_id']
    callback_id = request.json['callback_id']
    dial_timeout = request.json['dial_timeout']
    duration_limit = request.json['duration_limit']

    # origination_uuid = random.randint(1, 4294967296)
    m = hashlib.md5()
    m.update(now())
    mdate = m.hexdigest()
    origination_uuid = str(mdate) + "-" + str(random.randint(1, 4294967296))

    unique_id = random.randint(1, 4294967296)

    logging.info("lpt_callback | {} | {} | origination_uuid: {}".format(
        now(), str(unique_id), origination_uuid)
    )

    logging.info("lpt_local_channel | {} | {} | caller_id={} did={} clid={} call_id={} callback_id={}".format(
        now(), str(unique_id), caller_id, did, clid, call_id, callback_id)
    )
    logging.info("lpt_local_channel | {} | {} | dial_timeout={} duration_limit={}".format(
        now(), str(unique_id), dial_timeout, duration_limit)
    )

    originate_cmd = 'originate {originate_timeout=' + str(dial_timeout) + ',origination_uuid=' + str(
        origination_uuid) + ',ignore_early_media=true,origination_caller_id_number=' + str(anum) + ',unique_id=' + str(
        unique_id) + ',callback_id=' + str(callback_id) + ',dial_timeout=' + str(
        dial_timeout) + ',duration_limit=' + str(duration_limit) + '}loopback/cb_loc-leg-a_0' + str(
        bnum) + '/public callback-leg-b_' + str(bnum) + ' xml public'

#    originate_cmd = 'originate {originate_timeout=' + str(dial_timeout) + ',origination_uuid=' + str(
#        origination_uuid) + ',origination_caller_id_number=' + str(anum) + ',unique_id=' + str(
#        unique_id) + ',callback_id=' + str(callback_id) + ',dial_timeout=' + str(
#        dial_timeout) + ',duration_limit=' + str(duration_limit) + '}loopback/cb_loc-leg-a_0' + str(
#        bnum) + '/public callback-leg-b_' + str(bnum) + ' xml public'

    logging.info("lpt_local_channel | {} | {} | originate_cmd={}".format(
        now(), str(unique_id), originate_cmd)
    )

    node_ip = None
    flag_already_processed_that_clid = 0
    is_enabled_autofunnel_logic = True

    if clid:
        flag_already_processed_that_clid = check_exist_clid_in_key_member(clid)

        if flag_already_processed_that_clid == 1:
            node_ip = get_node_ip_from_pair_clid_node_ip(clid)
            if node_ip is None or node_ip == "None":
                pass
            else:
                is_enabled_autofunnel_logic = False
            logging.info("lpt_local_channel | {} | {} | get_node_ip_from_pair_clid_node_ip | that call for node_ip={}".format(
                now(), str(unique_id), node_ip)
            )
        else:
            node_ip = get_node_ip_from_clid(clid, nodes)
            if node_ip is None or node_ip == "None":
                pass
            else:
                is_enabled_autofunnel_logic = False
            logging.info("lpt_local_channel | {} | {} | get_node_ip_from_clid | that call for node_ip={}".format(
                now(), str(unique_id), node_ip)
            )

    if (node_ip is None or node_ip == "None") and call_id:
        node_ip = get_node_ip_from_call_id_redis(call_id, nodes)
        if node_ip is None or node_ip == "None":
            pass
        else:
            is_enabled_autofunnel_logic = False
        logging.info("lpt_local_channel | {} | {} | get_node_ip_from_call_id_redis | that call for node_ip={}".format(
            now(), str(unique_id), node_ip)
        )

        # balancer:
        if node_ip is None or node_ip == "None":
            esl_calls_count_string_node_1 = (execute_esl_command_slowly('show calls count', '31.131.249.26'))
            esl_calls_count_node_1 = int(esl_calls_count_string_node_1.split()[0])

            esl_calls_count_string_node_2 = (execute_esl_command_slowly('show calls count', '31.131.249.29'))
            esl_calls_count_node_2 = int(esl_calls_count_string_node_2.split()[0])

            logging.info("lpt_local_channel | {} | {} | esl_calls_count_node_1={}, esl_calls_count_node_2={}".format(
                now(), str(unique_id), esl_calls_count_node_1, esl_calls_count_node_2)
            )

            if esl_calls_count_node_1 == -1 and esl_calls_count_node_2 >= 0:
                # node_ip = redis_host_cl_2
                node_ip = nodes.get('fs-2')
                redis_ip = redis_host_cl_2

            elif esl_calls_count_node_2 == -1 and esl_calls_count_node_1 >= 0:
                # node_ip = redis_host_cl_1
                node_ip = nodes.get('fs-1')
                redis_ip = redis_host_cl_1

            elif esl_calls_count_node_1 >= 0 and esl_calls_count_node_1 <= esl_calls_count_node_2:
                # node_ip = redis_host_cl_1
                node_ip = nodes.get('fs-1')
                redis_ip = redis_host_cl_1

            elif esl_calls_count_node_2 >= 0 and esl_calls_count_node_2 <= esl_calls_count_node_1:
                # node_ip = redis_host_cl_2
                node_ip = nodes.get('fs-2')
                redis_ip = redis_host_cl_2


            if balancer_enable != 1:
                # node_ip = redis_host_cl_1
                node_ip = nodes.get('fs-1')
                redis_ip = redis_host_cl_1


            logging.info("lpt_local_channel | {} | {} | balancer | that call for node_ip={}".format(
                now(), str(unique_id), node_ip)
            )

    # if node_ip is None or node_ip == "None":
    #     node_ip = redis_host_cl_1

    if node_ip is None or node_ip == "None":
        random_bit = random.getrandbits(1)
        if bool(random_bit):
            # node_ip = redis_host_cl_2
            node_ip = nodes.get('fs-2')
            redis_ip = redis_host_cl_2

        else:
            # node_ip = redis_host_cl_1
            node_ip = nodes.get('fs-1')
            redis_ip = redis_host_cl_1


    call_case = clid.split('-')[1]
    logging.info("lpt_callback | {} | {} | call_case={}".format(
        now(), str(unique_id), call_case)
    )

    if re.search(r'autofunnel', call_case) and is_enabled_autofunnel_logic:
        logging.info("lpt_callback | {} | {} | that call is autofunnel".format(
            now(), str(unique_id))
        )
        # # node_ip = redis_host_cl_3
        # node_ip = nodes.get('fs-3')
        # redis_ip = redis_host_cl_3

        random_bet = random.getrandbits(1)
        if bool(random_bet):
            node_ip = nodes.get('fs-3')
            redis_ip = redis_host_cl_3

        else:
            node_ip = nodes.get('fs-4')
            redis_ip = redis_host_cl_4

    if flag_already_processed_that_clid == 0:
        execute_redis_command('SET', "pair_clid_node_ip-"+clid, node_ip, host=redis_host, port=redis_port, db=redis_db)
        execute_redis_command('SADD', "clid_key_member", clid, host=redis_host, port=redis_port, db=redis_db)

    execute_esl_command(originate_cmd, node_ip)

    logging.info("lpt_local_channel | {} | {} | originate sent cmd={}, node_ip={}".format(
        now(), str(unique_id), originate_cmd, node_ip)
    )

    return jsonify(
        {
            "status_code": "1",
            "status_info": "ok"
        }
    ), 200


# ################# UUID BRIDGE ##################


@app.route('/tapi/v1.0/bridge', methods=['POST'])
def uuid_bridge():
    # ur_id - unique_request_id
    ur_id = random.randint(1, 4294967296)
    method_name = uuid_bridge.__name__

    logging.info('{} | {} | {} | start'.format(method_name, now(), ur_id))

    if not request.json:
        logging.info("{} | {} | {} | the request doesn't have json header".format(method_name, now(), ur_id))
        return jsonify({'status': "nok"}), 400
    else:
        logging.info('{} | {} | {} | requset.json: {}'.format(method_name, now(), ur_id, request.data))


    if not request.json or not 'uuida' in request.json:
        logging.info("{} | {} | {} | abort request, because uuida wasn't set".format(method_name, now(), ur_id))
        abort(400)

    if not request.json or not 'uuidb' in request.json:
        logging.info("{} | {} | {} | abort request, because uuidb wasn't set".format(method_name, now(), ur_id))
        abort(400)

    uuid1 = str(request.json['uuida'])
    uuid2 = str(request.json['uuidb'])

    logging.info("{} | {} | {} | uuid1: {}".format(method_name, now(), ur_id, uuid1))
    logging.info("{} | {} | {} | uuid2: {}".format(method_name, now(), ur_id, uuid2))

    node_name = execute_redis_command('GET', "node_" + str(uuid1), host=redis_host, port=redis_port, db=redis_db)
    node_ip = nodes.get(node_name)
    node_redis_ip = redis_hosts.get(node_name)

    logging.info("{} | {} | {} | node_name: {}".format(method_name, now(), ur_id, node_name))
    logging.info("{} | {} | {} | node_ip: {}".format(method_name, now(), ur_id, node_ip))
    logging.info("{} | {} | {} | node_redis_ip: {}".format(method_name, now(), ur_id, node_redis_ip))

    # leonid
    if node_ip is None or node_ip == "None":
        node_name ='fs-1'
        node_ip = nodes.get('fs-1')
        node_redis_ip = redis_host_cl_1

        logging.info("{} | {} | {} | node_name: {}".format(method_name, now(), ur_id, node_name))
        logging.info("{} | {} | {} | node_ip: {}".format(method_name, now(), ur_id, node_ip))
        logging.info("{} | {} | {} | node_redis_ip: {}".format(method_name, now(), ur_id, node_redis_ip))

##################
    # для чего эта переменная?
    execute_redis_command('SET', 'bridge_' + uuid1, uuid2, host=node_redis_ip, port=redis_port, db=redis_db)

    # следующими двумя переменными мы проверяем были ли мы уже сбриджены с другими уидами,
    # дальше по этим переменным мы примем решение нужно нам склеивать вызовы или нет.
    uuid2_bridged_flag_record = execute_redis_command('GET', "bridged_flag_record-" + uuid1, host=node_redis_ip,
                                                      port=redis_port, db=redis_db)
    uuid1_bridged_flag_record = execute_redis_command('GET', "bridged_flag_record-" + uuid2, host=node_redis_ip,
                                                      port=redis_port, db=redis_db)

    logging.info(" {} | {} | {} | uuid1_bridged_flag_record: {}".format(method_name, now(),
                                                                        ur_id, uuid1_bridged_flag_record))
    logging.info(" {} | {} | {} | uuid2_bridged_flag_record: {}".format(method_name, now(),
                                                                        ur_id, uuid2_bridged_flag_record))

    if uuid2_bridged_flag_record is not None and uuid2_bridged_flag_record != str(uuid2):
        execute_redis_command('SET', 'flag_stick_together_record-' + uuid1, '1', host=node_redis_ip, port=redis_port,
                              db=redis_db)
        logging.info(" {} | {} | {} | flag_stick_together_record-{} = 1".format(method_name, now(), ur_id, uuid1))

    if uuid1_bridged_flag_record is not None and uuid1_bridged_flag_record != str(uuid1):
        execute_redis_command('SET', 'flag_stick_together_record-' + uuid2, '1', host=node_redis_ip, port=redis_port,
                              db=redis_db)
        logging.info(" {} | {} | {} | flag_stick_together_record-{} = 1".format(method_name, now(), ur_id, uuid2))

################

    execute_redis_command('SET', "bridged_flag_record-"+uuid1, uuid2, host=node_redis_ip, port=redis_port, db=redis_db)
    execute_redis_command('SET', "bridged_flag_record-"+uuid2, uuid1, host=node_redis_ip, port=redis_port, db=redis_db)

################

    call_type = execute_redis_command('GET', 'call_type_' + str(uuid1), host=redis_host, port=redis_port, db=redis_db)
    call_type_legb = execute_redis_command('GET', 'call_type_' + str(uuid2), host=redis_host, port=redis_port, db=redis_db)
    logging.info("{} | {} | {} | call_type: {}".format(method_name, now(), ur_id, call_type))
    logging.info("{} | {} | {} | call_type_legb: {}".format(method_name, now(), ur_id, call_type_legb))

    use_child_lega_uuid1 = execute_redis_command('GET', 'use_child_lega_uuid_' + uuid1, host=node_redis_ip, port=redis_port, db=redis_db)
    use_child_lega_uuid2 = execute_redis_command('GET', 'use_child_lega_uuid_' + uuid2, host=node_redis_ip, port=redis_port, db=redis_db)
    logging.info("{} | {} | {} | use_child_lega_uuid1: {}".format(method_name, now(), ur_id, use_child_lega_uuid1))
    logging.info("{} | {} | {} | use_child_lega_uuid2: {}".format(method_name, now(), ur_id, use_child_lega_uuid2))

    if use_child_lega_uuid1 == '1' and use_child_lega_uuid2 == '1':
        uuid1 = execute_redis_command('GET', 'child_lega_uuid_' + uuid1, host=node_redis_ip, port=redis_port, db=redis_db)
        uuid2 = execute_redis_command('GET', 'child_lega_uuid_' + uuid2, host=node_redis_ip, port=redis_port, db=redis_db)
    elif use_child_lega_uuid1 == '1' and call_type_legb == 'callback':
        uuid1 = execute_redis_command('GET', 'child_lega_uuid_' + uuid1, host=node_redis_ip, port=redis_port, db=redis_db)
        uuid2 = execute_redis_command('GET', 'callback_second_id_' + uuid2, host=redis_host, port=redis_port, db=redis_db)
    elif use_child_lega_uuid2 == '1':
        uuid2 = execute_redis_command('GET', 'child_lega_uuid_' + uuid2, host=node_redis_ip, port=redis_port, db=redis_db)
    else:
        if call_type == 'callback':
            uuid2 = execute_redis_command('GET', 'callback_second_id_' + uuid2, host=redis_host, port=redis_port, db=redis_db)
        elif call_type == 'in_call':
            uuid2 = execute_redis_command('GET', 'callback_second_id_' + uuid2, host=redis_host, port=redis_port, db=redis_db)
        elif call_type == 'call_transfer':
            uuid1 = execute_redis_command('GET', 'callback_second_id_' + uuid1, host=redis_host, port=redis_port, db=redis_db)
        elif call_type == 'call_release':
            uuid1 = execute_redis_command('GET', 'callback_second_id_' + uuid1, host=redis_host, port=redis_port, db=redis_db)

    logging.info("{} | {} | {} | esl cmd: uuid_bridge {} {}".format(method_name, now(), ur_id, uuid1, uuid2))

    # !!! Проверяем не зарелижены ли плечи вызова которые мы будем бриджить!
    call_hanguped_1 = execute_redis_command('GET', 'call_hanguped' + uuid1, host=node_redis_ip, port=redis_port, db=redis_db)
    call_hanguped_2 = execute_redis_command('GET', 'call_hanguped' + uuid2, host=node_redis_ip, port=redis_port, db=redis_db)
    logging.info("{} | {} | {} | call_hanguped_1: {}".format(method_name, now(), ur_id, call_hanguped_1))
    logging.info("{} | {} | {} | call_hanguped_2: {}".format(method_name, now(), ur_id, call_hanguped_2))

    if call_hanguped_1 == '1':
        esl_cmd = 'uuid_transfer'
        cmd = 'uuid_transfer ' + uuid2 + ' proceed_after_transfer'
    elif call_hanguped_2 == '1':
        esl_cmd = 'uuid_transfer'
        cmd = 'uuid_transfer ' + uuid1 + ' proceed_after_transfer'
    else:
        esl_cmd = 'uuid_bridge'
        cmd = 'uuid_bridge ' + uuid1 + ' ' + uuid2
        esl_uuid1 = uuid1
        esl_uuid2 = uuid2

    # !!! Проверяем не был ли плечо а затрансферено!
    call_transfered = execute_redis_command('GET', 'call_transfered_' + uuid1, host=redis_host, port=redis_port, db=redis_db)
    logging.info("{} | {} | {} | call_transfered: {}".format(method_name, now(), ur_id, call_transfered))

    # ??? Не совсем понтяно, что тут проверяем так как зарелижен или нет вызов проверили выше!
    end_callback_sended = execute_redis_command('GET', 'end_callback_sended-' + uuid1, host=node_redis_ip, port=redis_port, db=redis_db)
    logging.info("{} | {} | {} | end_callback_sended: {}".format(method_name, now(), ur_id, end_callback_sended))

    if call_transfered == '1' and end_callback_sended == '1':
        logging.info("{} | {} | {} | call_transfered=='1' & end_callback_sended=='1'".format(method_name, now(), ur_id))
        uuid_bridged = execute_redis_command('GET', "bridged_with-" + uuid1, host=node_redis_ip, port=redis_port, db=redis_db)
        logging.info("{} | {} | {} | uuid_bridged: {}".format(method_name, now(), ur_id, uuid_bridged))
        esl_cmd = 'uuid_bridge'
        cmd = 'uuid_bridge ' + uuid_bridged + ' ' + uuid2
        esl_uuid1 = uuid_bridged
        esl_uuid2 = uuid2
    elif call_transfered != '1' and end_callback_sended == '1':
        logging.info("{} | {} | {} | call_transfered!='1' & end_callback_sended=='1'".format(method_name, now(), ur_id))
        esl_cmd = 'uuid_transfer'
        cmd = 'uuid_transfer ' + uuid2 + ' proceed_after_transfer'

    execute_esl_command(cmd, node_ip)

    for key, value in nodes.items():
        if value != node_ip:
            execute_esl_command(cmd, value)

    logging.info("{} | {} | {} | sent esl cmd: {}".format(method_name, now(), ur_id, cmd))

    if esl_cmd == 'uuid_bridge':
        execute_redis_command('SET', "bridged_with-" + esl_uuid1, esl_uuid2, host=node_redis_ip, port=redis_port, db=redis_db)
        execute_redis_command('SET', "bridged_with-" + esl_uuid2, esl_uuid1, host=node_redis_ip, port=redis_port, db=redis_db)
        execute_redis_command('SET', "bridged-" + esl_uuid1, '1', host=node_redis_ip, port=redis_port, db=redis_db)
        execute_redis_command('SET', "bridged-" + esl_uuid2, '1', host=node_redis_ip, port=redis_port, db=redis_db)

    return jsonify(
        {
            "status_code": "1",
            "status_info": "ok"
        }
    ), 200


# ################# UUID KILL ##################

@app.route('/tapi/v1.0/kill', methods=['POST'])
def uuid_kill():
    # ur_id - unique_request_id
    ur_id = random.randint(1, 4294967296)
    method_name = uuid_kill.__name__

    logging.info('{} | {} | {} | start'.format(method_name, now(), ur_id))

    if not request.json:
        logging.info("{} | {} | {} | the request doesn't have json header".format(method_name, now(), ur_id))
        return jsonify({'status': "nok"}), 400
    else:
        logging.info('{} | {} | {} | requset.json: {}'.format(method_name, now(), ur_id, request.data))

    if not request.json or not 'uuid' in request.json:
        logging.info("{} | {} | {} | abort request, because uuid wasn't set".format(method_name, now(), ur_id))
        abort(400)

    uuid = str(request.json['uuid'])
    logging.info("{} | {} | {} | uuid: {}".format(method_name, now(), ur_id, uuid))

    node_name = execute_redis_command('GET', "node_" + str(uuid), host=redis_host, port=redis_port, db=redis_db)

    # !!! Существует проблема в том что не всегда когда прилетает килл, имя ноды уже записано в основной редис!
    # Из-за этого в конце я отправляю команду на все ноды. НЕОБХОДИМО НАЙТИ РЕШЕНИЕ ЭТОЙ ПРОБЛЕМЫ
    # (как вариант записывать инфу о вызове на тапи в вмомент инициации вызова)!
    if not node_name or node_name not in nodes.keys():
        logging.info("{} | {} | {} | node_name: {}".format(method_name, now(), ur_id, node_name))
        logging.info("{} | {} | {} | try to use random node_name from nodes".format(method_name, now(), ur_id))
        node_name = random.choice(list(nodes.keys()))

    node_ip = nodes.get(node_name)
    node_redis_ip = redis_hosts.get(node_name)

    logging.info("{} | {} | {} | node_name: {}".format(method_name, now(), ur_id, node_name))
    logging.info("{} | {} | {} | node_ip: {}".format(method_name, now(), ur_id, node_ip))
    logging.info("{} | {} | {} | node_redis_ip: {}".format(method_name, now(), ur_id, node_redis_ip))

    execute_redis_command('SET', 'back_kill_uuid_'+ uuid, '1', host=node_redis_ip, port=redis_port, db=redis_db)

    skip_flag = execute_redis_command('GET', 'temp_callback_id-'+str(uuid), host=node_redis_ip, port=redis_port, db=redis_db)
    logging.info("{} | {} | {} | skip_flag: {}".format(method_name, now(), ur_id, skip_flag))

    if skip_flag == '1':
        logging.info("{} | {} | {} | skip uuid_kill".format(method_name, now(), ur_id))
        return jsonify({'status': "nok"}), 400

    use_child_lega_uuid = execute_redis_command('GET', 'use_child_lega_uuid_' + uuid, host=node_redis_ip, port=redis_port, db=redis_db)
    logging.info("{} | {} | {} | use_child_lega_uuid: {}".format(method_name, now(), ur_id, use_child_lega_uuid))

    if use_child_lega_uuid == '1':
        logging.info("{} | {} | {} | use_child_lega_uuid == '1', try to get child uuid".format(method_name, now(), ur_id))
        uuid = execute_redis_command('GET', 'child_lega_uuid_' + uuid, host=node_redis_ip, port=redis_port, db=redis_db)
        logging.info("{} | {} | {} | uuid: {}".format(method_name, now(), ur_id, uuid))

    logging.info("{} | {} | {} | esl cmd: uuid_kill {}".format(method_name, now(), ur_id, uuid))

    cmd = 'uuid_kill ' + uuid
    execute_esl_command(cmd, node_ip)

    execute_redis_command('SET', 'killed_' + uuid, '1', host=node_redis_ip, port=redis_port, db=redis_db)
    execute_redis_command('SET', 'back_send_cmd_uuid_kill-' + uuid, '1', host=node_redis_ip, port=redis_port, db=redis_db)

    for key, value in nodes.items():
        if value != node_ip:
            execute_esl_command(cmd, value)
            execute_redis_command('SET', 'killed_' + uuid, '1', host=redis_hosts.get(key), port=redis_port, db=redis_db)
            execute_redis_command('SET', 'back_send_cmd_uuid_kill-' + uuid, '1', host=redis_hosts.get(key), port=redis_port, db=redis_db)

    logging.info("{} | {} | {} | sent esl cmd: {}".format(method_name, now(), ur_id, cmd))

    return jsonify(
        {
            "status_code": "1",
            "status_info": "ok"
        }
    ), 200


# ################# UUID TRANSFER ##################

@app.route('/tapi/v1.0/transfer', methods=['POST'])
def uuid_transfer():
    ur_id = random.randint(1, 4294967296)
    method_name = uuid_transfer.__name__

    logging.info('{} | {} | {} | start'.format(method_name, now(), ur_id))

    if not request.json:
        logging.info("{} | {} | {} | the request doesn't have json header".format(method_name, now(), ur_id))
        return jsonify({'status': "nok"}), 400
    else:
        logging.info('{} | {} | {} | requset.json: {}'.format(method_name, now(), ur_id, request.data))

    if not request.json or not 'uuid' in request.json:
        logging.info("{} | {} | {} | abort request, because uuid wasn't set".format(method_name, now(), ur_id))
        abort(400)

    uuid = str(request.json['uuid'])
    logging.info("{} | {} | {} | uuid: {}".format(method_name, now(), ur_id, uuid))

    node_name = execute_redis_command('GET', "node_" + str(uuid), host=redis_host, port=redis_port, db=redis_db)

    # !!! Существует проблема в том что не всегда когда прилетает килл, имя ноды уже записано в основной редис!
    # Из-за этого в конце я отправляю команду на все ноды. НЕОБХОДИМО НАЙТИ РЕШЕНИЕ ЭТОЙ ПРОБЛЕМЫ
    # (как вариант записывать инфу о вызове на тапи в вмомент инициации вызова)!
    if not node_name or node_name not in nodes.keys():
        logging.info("{} | {} | {} | node_name: {}".format(method_name, now(), ur_id, node_name))
        logging.info("{} | {} | {} | try to use random node_name from nodes".format(method_name, now(), ur_id))
        node_name = random.choice(list(nodes.keys()))

    node_ip = nodes.get(node_name)
    node_redis_ip = redis_hosts.get(node_name)

    logging.info("{} | {} | {} | node_name: {}".format(method_name, now(), ur_id, node_name))
    logging.info("{} | {} | {} | node_ip: {}".format(method_name, now(), ur_id, node_ip))
    logging.info("{} | {} | {} | node_redis_ip: {}".format(method_name, now(), ur_id, node_redis_ip))

    use_child_lega_uuid = execute_redis_command('GET', 'use_child_lega_uuid_' + uuid, host=node_redis_ip, port=redis_port, db=redis_db)
    logging.info("{} | {} | {} | use_child_lega_uuid: {}".format(method_name, now(), ur_id, use_child_lega_uuid))

    if use_child_lega_uuid == '1':
        logging.info("{} | {} | {} | use_child_lega_uuid == '1', try to get child uuid".format(method_name, now(), ur_id))
        uuid = execute_redis_command('GET', 'child_lega_uuid_' + uuid, host=node_redis_ip, port=redis_port, db=redis_db)
        logging.info("{} | {} | {} | uuid: {}".format(method_name, now(), ur_id, uuid))

    execute_redis_command('SET', 'call_transfered_' + uuid, '0', host=node_redis_ip, port=redis_port, db=redis_db)

    logging.info("{} | {} | {} | redis set: leg_transferred_by_back/{} 1".format(method_name, now(), ur_id, uuid))
    execute_redis_command('SET', 'leg_transferred_by_back/' + uuid, '1', host=node_redis_ip, port=redis_port, db=redis_db)

    logging.info("{} | {} | {} | esl cmd: uuid_transfer {} proceed_after_transfer".format(method_name, now(), ur_id, uuid))

    cmd = 'uuid_transfer ' + uuid + ' proceed_after_transfer'
    execute_esl_command(cmd, node_ip)

    for key, value in nodes.items():
        if value != node_ip:
            execute_esl_command(cmd, value)

    logging.info("{} | {} | {} | sent esl cmd: {}".format(method_name, now(), ur_id, cmd))

    return jsonify(
        {
            "status_code": "1",
            "status_info": "ok"
        }
    ), 200


#
# Client SIP account method:
#
#
# метод необходим чтобы вывести информацию о клиентском SIP trunk по ид
#
# /tapi/v1.0/sip_account/<int:account_id>
# "status": str,  # ('REGED','UNREGED','BLOCKED')
@app.route('/tapi/v1.0/sip_account_2/<int:account_id>', methods=['GET'])
def get_sip_account_by_id(account_id):
    unique_request_id = random.randint(1, 4294967296)
    method_name = get_sip_account_by_id.__name__

    print('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | account_id: {}'.format(method_name, now(), unique_request_id, account_id))

    if not exist_sip_account_id(unique_request_id, account_id):
        json_response = {
            "status_code": 11,
            "status_info": "not found"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400

    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')
    x = conn.cursor()
    try:
        sql_select_name_by_id = 'select name, is_blocked from ext_sip_accounts where id = {};'.format(account_id)

        print('{} | {} | {} | '
              'sql_select_name_by_id: {}'.format(method_name, now(), unique_request_id, sql_select_name_by_id))
        logging.info('{} | {} | {} | '
                     'sql_select_name_by_idt: {}'.format(method_name, now(), unique_request_id, sql_select_name_by_id))

        x.execute(sql_select_name_by_id)
        sql_select_result = x.fetchone()
        print('{} | {} | {} | sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))
        logging.info('{} | {} | {} | '
                     'sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))

        account_name = sql_select_result[0]
        is_blocked = sql_select_result[1]

        if is_blocked:
            status = 'BLOCKED'
        else:
            result_status_request = execute_esl_command_slowly('sofia status gateway {}'.format(account_name), esl_host)
            status = parse_esl_status_response(unique_request_id, result_status_request)

            if status != 'REGED':
                status = 'UNREGED'

        json_response = {
            "id": account_id,
            "status": status,
        }

        conn.commit()

    except:
        print("{} | {} | {} | can't connect to make select request by id".format(method_name, now(), unique_request_id))
        logging.info("{} | {} | {} | can't connect to "
                     "make select request by id".format(method_name, now(), unique_request_id))

        conn.rollback()
        conn.close()
        json_response = {
                "status_code": 0,
                "status_info": "request failed"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 500

    conn.close()

    print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
    logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

    return jsonify(json_response), 200


#
# Client SIP Trunk method:
#
# метод необходим чтобы вывести информацию о всех клиентских SIP trunk созданных в системе
#
@app.route('/tapi/v1.0/client_trunk', methods=['GET'])
def get_client_trunk():
    unique_request_id = random.randint(1, 4294967296)
    method_name = get_client_trunk.__name__

    print('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | start'.format(method_name, now(), unique_request_id))

    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')
    x = conn.cursor()
    try:
        sql_select_request = 'select id,proxy,port,username,password,flag_auth,client_id from client_trunk;'
        print("{} | {} | {} | sql_select_request: {}".format(method_name, now(), unique_request_id, sql_select_request))
        logging.info('{} | {} | {} | '
                     'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request))

        x.execute(sql_select_request)
        sql_select_result = x.fetchmany(SELECT_LIMIT)

        print("{} | {} | {} | sql_select_result: {}".format(method_name, now(), unique_request_id, sql_select_result))
        logging.info('{} | {} | {} | '
                     'sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))

        json_response = []
        for s in sql_select_result:
            print("{} | {} | {} | {}".format(method_name, now(), unique_request_id, s))
            logging.info('{} | {} | {} | {}'.format(method_name, now(), unique_request_id, s))

            trunk_id = s[0]
            proxy = s[1]
            port = s[2]
            username = s[3]
            password = s[4]
            flag_auth = s[5]
            client_id = s[6]

            sip_trunk = {
                "trunk_id": trunk_id,
                "host": proxy,
                "port": port,
                "username": username,
                "password": password,
                "auth": flag_auth,
                "client_id": client_id
            }
            json_response.append(sip_trunk)

        conn.commit()

    except:
        print("{} | {} | {} | can't connect to make select request".format(method_name, now(), unique_request_id))
        logging.info("{} | {} | {} | can't connect to make select req.".format(method_name, now(), unique_request_id))

        conn.rollback()
        conn.close()
        json_response = {
                "status_code": 0,
                "status_info": "request failed"
        }

        print("{} | {} | {} | json_response: {}".format(method_name, now(), unique_request_id, json_response))
        logging.info("{} | {} | {} | json_response: {}".format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 500

    conn.close()
    print("{} | {} | {} | json_response: {}".format(method_name, now(), unique_request_id, json_response))
    logging.info("{} | {} | {} | json_response: {}".format(method_name, now(), unique_request_id, json_response))

    return jsonify(json_response), 200


#
# метод необходим чтобы вывести информацию о клиентском SIP trunk по ид
#
@app.route('/tapi/v1.0/client_trunk/<int:trunk_id>', methods=['GET'])
def get_client_trunk_by_id(trunk_id):
    unique_request_id = random.randint(1, 4294967296)
    method_name = get_client_trunk_by_id.__name__

    print('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | start'.format(method_name, now(), unique_request_id))

    if not exist_trunk_id(unique_request_id, trunk_id):
        json_response = {
            "status_code": 11,
            "status_info": "not found"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400

    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')
    x = conn.cursor()
    try:
        sql_select_request_by_id = 'select proxy, port, username, password, flag_auth, client_id from client_trunk ' \
                             'where id = {};'.format(trunk_id)

        print('{} | {} | {} | '
              'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))
        logging.info('{} | {} | {} | '
                     'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))

        x.execute(sql_select_request_by_id)
        sql_select_result = x.fetchone()
        print('{} | {} | {} | sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))
        logging.info('{} | {} | {} | '
                     'sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))

        proxy = sql_select_result[0]
        port = sql_select_result[1]
        username = sql_select_result[2]
        password = sql_select_result[3]
        flag_auth = sql_select_result[4]
        if flag_auth == 0:
            flag_auth = False
        elif flag_auth == 1:
            flag_auth = True

        client_id = sql_select_result[5]

        result_status_request = execute_esl_command_slowly('sofia status gateway ' + CUSTOM_TRUNK_PREFIX + str(trunk_id), redis_host)
        # state = 'REGED'
        state = parse_esl_status_response(unique_request_id, result_status_request)

        if state == 'Parsing_Error':
            state = 'UNREGED'

        json_response = {
            "trunk_id": trunk_id,
            "host": proxy,
            "port": port,
            "username": username,
            "password": password,
            "auth": flag_auth,
            "client_id": client_id,
            "state": state,
        }

        conn.commit()

    except:
        print("{} | {} | {} | can't connect to make select request by id".format(method_name, now(), unique_request_id))
        logging.info("{} | {} | {} | can't connect to "
                     "make select request by id".format(method_name, now(), unique_request_id))

        conn.rollback()
        conn.close()
        json_response = {
                "status_code": 0,
                "status_info": "request failed"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 500

    conn.close()

    print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
    logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

    return jsonify(json_response), 200


#
# Метод используется баскендом для создание нового клиентского SIP trunk:
#
@app.route('/tapi/v1.0/client_trunk', methods=['POST'])
def add_client_trunk():
    unique_request_id = random.randint(1, 4294967296)
    method_name = add_client_trunk.__name__

    print('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | start'.format(method_name, now(), unique_request_id))

    if not request.json:
        json_response = {
            "status_code": 12,
            "status_info": "bad param"
        }

        print('{} | {} | {} | json_responce: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_resp: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400
    else:
        print('{} | {} | {} | request.json: {}'.format(method_name, now(), unique_request_id, request.data))
        logging.info('{} | {} | {} | req.json: {}'.format(method_name, now(), unique_request_id, request.data))

    # !!! надо дописать исключения!

    proxy = request.json['host']

    if 'port' not in request.json:
        port = 5060
    elif request.json['port'] == 0:
        port = 5060
    else:
        port = request.json['port']

    if not request.json['host'] or request.json['host'] == False:
        flag_auth = False
        username = None
        password = None
    else:
        flag_auth = request.json['flag_auth']
        username = request.json['username']
        password = request.json['password']

    if 'client_id' not in request.json:
        client_id = None
    else:
        client_id = request.json['client_id']

    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')
    x = conn.cursor()
    try:
        if not client_id:
            sql_insert_request = "insert into client_trunk (proxy,port,username,password,flag_auth) values " \
                             "('{}',{},'{}','{}',{})".format(proxy, port, username, password, flag_auth)
        else:
            sql_insert_request = "insert into client_trunk (proxy,port,username,password,flag_auth,client_id) values " \
                             "('{}',{},'{}','{}',{},{})".format(proxy, port, username, password, flag_auth, client_id)

        print('{} | {} | {} | sql_insert_request: {}'.format(method_name, now(), unique_request_id, sql_insert_request))
        logging.info('{} | {} | {} | '
                     'sql_insert_request: {}'.format(method_name, now(), unique_request_id, sql_insert_request))

        x.execute(sql_insert_request)

        # !!! Необходимо переделать бд сделать уникальным большее количество параметров, как следствие изменить селект!
        sql_select_request_id = "select id from client_trunk where proxy = '{}' and port = {} and username = '{}' " \
                                "and password = '{}'".format(proxy, port, username, password)

        print('{} | {} | {} | '
              'sql_select_request_id: {}'.format(method_name, now(), unique_request_id, sql_select_request_id))
        logging.info('{} | {} | {} | '
                     'sql_select_request_id: {}'.format(method_name, now(), unique_request_id, sql_select_request_id))

        x.execute(sql_select_request_id)

        trunk_id = x.fetchone()[0]

        print('{} | {} | {} | trunk_id: {}'.format(method_name, now(), unique_request_id, trunk_id))
        logging.info('{} | {} | {} | trunk_id: {}'.format(method_name, now(), unique_request_id, trunk_id))

        # # !!! Необходимо добавить нормальные переменные адресов, вместо использования переменных редиса (redis_host)!
        # execute_redis_command('SADD', 'custom_sip_trunk_id', trunk_id, host=redis_host, port=redis_port, db=redis_db)
        # custom_sip_trunk_id = execute_redis_command('SMEMBERS', 'custom_sip_trunk_id',
        #                                             host=redis_host, port=redis_port, db=redis_db)
        #
        # print('{} | {} | {} | custom_sip_trunk_id: {}, type: {}'.
        #       format(method_name, now(), unique_request_id, custom_sip_trunk_id, type(custom_sip_trunk_id)))
        # logging.info('{} | {} | {} | custom_sip_trunk_id: {}, type: {}'.
        #              format(method_name, now(), unique_request_id, custom_sip_trunk_id, type(custom_sip_trunk_id)))

        conn.commit()

        # Дальше блок кода взаимодействия с Freeswitch:
        # - создание XML файла
        # - запрос в ESL на перечитывание новых транков
        create_xml_file_for_custom_sip_user_trunk(proxy, port, username, password, XML_CUSTOM_TRUNK_FILE_PATH,
                                                  CUSTOM_TRUNK_PREFIX + str(trunk_id))
        # execute_esl_command('sofia profile external_client_trunk rescan ' + CUSTOM_TRUNK_PREFIX + str(trunk_id), redis_host)
        execute_esl_command('sofia profile external_client_trunk rescan', esl_host)

    except:
        print("{} | {} | {} | can't connect to make insert request".format(method_name, now(), unique_request_id))
        logging.info("{} | {} | {} | "
                     "can't connect to make insert request".format(method_name, now(), unique_request_id))

        conn.rollback()
        conn.close()
        json_response = {
                "status_code": 0,
                "status_info": "request failed"
            }

        print("{} | {} | {} | json_response: {}".format(method_name, now(), unique_request_id, json_response))
        logging.info("{} | {} | {} | json_response: {}".format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 500

    conn.close()
    json_response = {
            "trunk_id": trunk_id,
            "status_code": "1",
            "status_info": "ok"
        }

    print("{} | {} | {} | json_response: {}".format(method_name, now(), unique_request_id, json_response))
    logging.info("{} | {} | {} | json_response: {}".format(method_name, now(), unique_request_id, json_response))

    return jsonify(json_response), 200

#
# Метод используется баскендом для изменения параметров клиентского SIP trunk:
#
@app.route('/tapi/v1.0/client_trunk', methods=['PUT'])
def upd_client_trunk():
    unique_request_id = random.randint(1, 4294967296)
    method_name = upd_client_trunk.__name__

    print('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | start'.format(method_name, now(), unique_request_id))

    if not request.json:
        json_response = {
            "status_code": 10,
            "status_info": "bad id"
        }
        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_resp: {}'.format(method_name, now(), unique_request_id, json_response))
        return jsonify(json_response), 400
    else:
        print('{} | {} | {} | request.json: {}'.format(method_name, now(), unique_request_id, request.data))
        logging.info('{} | {} | {} | req.json: {}'.format(method_name, now(), unique_request_id, request.data))

    if 'trunk_id' not in request.json:
        json_response = {
            "status_code": 10,
            "status_info": "bad id"
        }
        print('{} | {} | {} | bad id'.format(method_name, now(), unique_request_id))
        logging.info('{} | {} | {} | bad id'.format(method_name, now(), unique_request_id))
        return jsonify(json_response), 400

    # !!! надо дописать исключения!

    trunk_id = request.json['trunk_id']

    if not exist_trunk_id(unique_request_id, trunk_id):
        json_response = {
            "status_code": 11,
            "status_info": "not found"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400

    proxy = request.json['host']

    if 'port' not in request.json:
        port = 5060
    elif request.json['port'] == 0:
        port = 5060
    else:
        port = request.json['port']

    username = request.json['username']
    password = request.json['password']
    flag_auth = request.json['flag_auth']

#    client_id = request.json['client_id']
    if 'client_id' not in request.json:
        client_id = None
    else:
        client_id = request.json['client_id']

    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')
    x = conn.cursor()
    try:
        if not client_id:
            sql_update_request = "update client_trunk set " \
                                 "proxy = '{}', " \
                                 "port = {}, " \
                                 "username = '{}', " \
                                 "password = '{}', " \
                                 "flag_auth = {} " \
                                 "where id = {};".format(proxy, port, username, password, flag_auth, trunk_id)

        else:
            sql_update_request = "update client_trunk set " \
                                 "proxy = '{}', " \
                                 "port = {}, " \
                                 "username = '{}', " \
                                 "password = '{}', " \
                                 "flag_auth = {}, " \
                                 "client_id = {} " \
                                 "where id ={};".format(proxy, port, username, password, flag_auth, client_id, trunk_id)

        print('{} | {} | {} | sql_insert_request: {}'.format(method_name, now(), unique_request_id, sql_update_request))
        logging.info('{} | {} | {} | '
                     'sql_insert_request: {}'.format(method_name, now(), unique_request_id, sql_update_request))

        x.execute(sql_update_request)
        conn.commit()

        # Дальше блок кода взаимодействия с Freeswitch:
        # - удаление XML файла
        # - запрос в ESL на удаления транка из БД Freeswitch
        delete_xml_file(XML_CUSTOM_TRUNK_FILE_PATH, CUSTOM_TRUNK_PREFIX + str(trunk_id), unique_request_id)
        execute_esl_command('sofia profile external_client_trunk killgw ' + CUSTOM_TRUNK_PREFIX + str(trunk_id), esl_host)

        # - создание XML файла
        # - запрос в ESL на перечитывание новых транков
        create_xml_file_for_custom_sip_user_trunk(proxy, port, username, password, XML_CUSTOM_TRUNK_FILE_PATH,
                                                  CUSTOM_TRUNK_PREFIX + str(trunk_id))
        execute_esl_command('sofia profile external_client_trunk rescan', esl_host)

    except:
        print("{} | {} | {} | can't connect to make update request".format(method_name, now(), unique_request_id))
        logging.info("{} | {} | {} | can't connect to make update req.".format(method_name, now(), unique_request_id))

        conn.rollback()
        conn.close()
        json_response = {
                "status_code": 0,
                "status_info": "request failed"
            }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 500

    conn.close()
    json_response = {
            "status_code": "1",
            "status_info": "ok"
        }

    print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
    logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

    return jsonify(json_response), 200


# Метод необходим для удаления клиентского SIP trunk:
@app.route('/tapi/v1.0/client_trunk', methods=['DELETE'])
def del_client_trunk():
    unique_request_id = random.randint(1, 4294967296)
    method_name = del_client_trunk.__name__

    print('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | start'.format(method_name, now(), unique_request_id))

    if not request.json:
        json_response = {
            "status_code": 0,
            "status_info": "bad id"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400
    else:
        print('{} | {} | {} | request.json: {}'.format(method_name, now(), unique_request_id, request.data))
        logging.info('{} | {} | {} | req.json: {}'.format(method_name, now(), unique_request_id, request.data))

    logging.info('{} | {} | {} | 1'.format(method_name, now(), unique_request_id))

    if 'trunk_id' not in request.json:
        json_response = {
            "status_code": 0,
            "status_info": "bad id"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400

    trunk_id = request.json['trunk_id']

    logging.info('{} | {} | {} | before exist_trunk_id'.format(method_name, now(), unique_request_id))

    if not exist_trunk_id(unique_request_id, trunk_id):
        json_response = {
            "status_code": 11,
            "status_info": "not found"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400

    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')
    x = conn.cursor()
    try:
        sql_delete_request = 'delete from client_trunk ' \
                             'where id = {};'.format(trunk_id)

        print('{} | {} | {} | sql_delete_request: {}'.format(method_name, now(), unique_request_id, sql_delete_request))
        logging.info('{} | {} | {} | '
                     'sql_delete_request: {}'.format(method_name, now(), unique_request_id, sql_delete_request))

        x.execute(sql_delete_request)
        conn.commit()

        # Дальше блок кода взаимодействия с Freeswitch:
        # - удаление XML файла
        # - запрос в ESL на удаления транка из БД Freeswitch
        delete_xml_file(XML_CUSTOM_TRUNK_FILE_PATH, CUSTOM_TRUNK_PREFIX + str(trunk_id), unique_request_id)
        execute_esl_command('sofia profile external_client_trunk killgw ' + CUSTOM_TRUNK_PREFIX + str(trunk_id), esl_host)

    except:
        print("{} | {} | {} | can't connect to make delete request".format(method_name, now(), unique_request_id))
        logging.info("{} | {} | {} | can't connect to make delete req.".format(method_name, now(), unique_request_id))

        conn.rollback()
        conn.close()
        json_response = {
                "status_code": 0,
                "status_info": "request failed"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 500

    conn.close()
    json_response = {
            "status_code": "1",
            "status_info": "ok"
    }

    print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
    logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

    return jsonify(json_response), 200


#
# метод необходим чтобы вывести информацию о сторонних SIP учетках по id:
#
@app.route('/tapi/v1.0/sip_account/<int:account_id>', methods=['GET'])
def get_ext_sip_account_by_id(account_id):
    unique_request_id = random.randint(1, 4294967296)
    method_name = get_ext_sip_account_by_id.__name__

    print('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | start'.format(method_name, now(), unique_request_id))

    if not exist_sip_account_id(unique_request_id, account_id):
        json_response = {
            "status_code": 11,
            "status_info": "not found"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400

    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')
    x = conn.cursor()
    try:
        sql_select_request_by_id = 'select  name, username, password, domain, proxy, port, expires, number, ' \
                                   'server, is_blocked, is_disabled from ext_sip_accounts where id = {};'.format(account_id)

        print('{} | {} | {} | '
              'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))
        logging.info('{} | {} | {} | '
                     'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))

        x.execute(sql_select_request_by_id)
        sql_select_result = x.fetchone()
        print('{} | {} | {} | sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))
        logging.info('{} | {} | {} | '
                     'sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))
        print('0')

        name = sql_select_result[0]
        username = sql_select_result[1]
        password = sql_select_result[2]
        domain = sql_select_result[3]
        proxy = sql_select_result[4]
        port = sql_select_result[5]
        expires = sql_select_result[6]
        number = sql_select_result[7]
        server = sql_select_result[8]
        is_blocked = sql_select_result[9]
        is_disabled = sql_select_result[10]

        print('1')

        if is_blocked == '0':
            is_blocked = False
        elif is_blocked == '1':
            is_blocked = True
        elif is_blocked == 0:
            is_blocked = False
        elif is_blocked == 1:
            is_blocked = True

        if is_disabled == '0':
            is_disabled = False
        elif is_disabled == '1':
            is_disabled = True
        elif is_disabled == 0:
            is_disabled = False
        elif is_disabled == 1:
            is_disabled = True

        if is_blocked:
            state = 'BLOCKED'
        elif is_disabled:
            state = 'REGED'
        else:
            result_status_request = execute_esl_command_slowly('sofia status gateway ' + str(name), esl_host)
            state = parse_esl_status_response(unique_request_id, result_status_request)

        print('2')

        if state != 'BLOCKED' and state != 'REGED':
            state = 'UNREGED'

        json_response = {
            "id": account_id,
            "name": name,
            "status": state,
        }

        print('json_response:', json_response)

        conn.commit()

    except:
        print("{} | {} | {} | can't connect to make select request by id".format(method_name, now(), unique_request_id))
        logging.info("{} | {} | {} | can't connect to "
                     "make select request by id".format(method_name, now(), unique_request_id))

        conn.rollback()
        conn.close()
        json_response = {
                "status_code": 0,
                "status_info": "request failed"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 500

    conn.close()

    print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
    logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

    return jsonify(json_response), 200


#
# метод для разблокировки SIP аккаунтов по дате
#
@app.route('/tapi/v1.0/sip_account/unblock', methods=['GET'])
def unblock_sip_account_by_date():
    unique_request_id = random.randint(1, 4294967296)
    method_name = get_ext_sip_account_by_id.__name__

    args = request.args
    date = args.get('date')

    print('{} | {} | {} | start'.format(method_name, now(), unique_request_id))
    logging.info('{} | {} | {} | start'.format(method_name, now(), unique_request_id))

    if not date or validate_date(unique_request_id, date):
        json_response = {
            "status_code": 12,
            "status_info": "bad param",
            "date": date,
            "date_format": "%Y-%m-%d"
        }

        print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
        logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

        return jsonify(json_response), 400

    unblock_sip_accounts_list = os.listdir(BLOCK_SIP_ACCOUNT_PATH + date)
    logging.info('{} | {} | {} | unblock_sip_accounts_list: {}'.format(method_name, now(), unique_request_id,
                                                                        unblock_sip_accounts_list))

    for sip_account in unblock_sip_accounts_list:
        unblocking_path = UNBLOCK_SIP_ACCOUNT_PATH + date + '/'
        try:
            logging.info('{} | {} | {} | sip_account: {}'.format(method_name, now(), unique_request_id,
                                                                                sip_account))

            logging.info('{} | {} | {} | copy: {} {}'.format(method_name, now(), unique_request_id,
                                                             BLOCK_SIP_ACCOUNT_PATH + date + '/' + sip_account,
                                                             XML_USER_FILE_PATH + sip_account))
            shutil.copy2(BLOCK_SIP_ACCOUNT_PATH + date + '/' + sip_account, XML_USER_FILE_PATH + sip_account)

            logging.info('{} | {} | {} | path: {}{}'.format(method_name, now(), unique_request_id,
                                                            unblocking_path, sip_account))

            check_path(unique_request_id, unblocking_path)

            logging.info('{} | {} | {} | move: {} {}'.format(method_name, now(), unique_request_id,
                                                             BLOCK_SIP_ACCOUNT_PATH + date + '/' + sip_account,
                                                             unblocking_path + sip_account))

            shutil.move(BLOCK_SIP_ACCOUNT_PATH + date + '/' + sip_account, unblocking_path + sip_account)

            unblock_sip_account(unique_request_id, sip_account[0:-4:])

        except IOError as e:
            print('{} | {} | {} | not found: {}'.format(method_name, now(), unique_request_id,
                                                        unblocking_path + sip_account))

    cmd = 'sofia profile external rescan'
    print('{} | {} | {} | esl cmd: {}'.format(method_name, now(), unique_request_id, cmd))
    logging.info('{} | {} | {} | esl cmd: {}'.format(method_name, now(), unique_request_id, cmd))
    execute_esl_command(cmd, esl_host)

    json_response = {
        "status_code": 1,
        "status_info": "successfully unblock"
    }

    print('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))
    logging.info('{} | {} | {} | json_response: {}'.format(method_name, now(), unique_request_id, json_response))

    return jsonify(json_response), 200


#
# Блок обработки общих негативных кейсов:
@app.errorhandler(404)
def not_found(error):
    return make_response(jsonify({'error': 'Not found'}), 404)


if __name__ == '__main__':
    app.run(host=redis_host, port="80", debug=True)

