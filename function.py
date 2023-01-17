#!flask/bin/python


# balancer enable:
balancer_enable = 1
nodes = {'fs-1': '172.16.100.189', 'fs-2': '172.16.100.108', 'fs-3': '172.16.100.21', 'fs-4': '172.16.100.14'}

# logging param:
log_path = "/var/log/freeswitch/backend_dialog.log"

# redis connect param:
redis_host = '172.16.100.46'
redis_host_cl_1 = '172.16.100.170'
redis_host_cl_2 = '172.16.100.45'
redis_host_cl_3 = '172.16.100.220'
redis_host_cl_4 = '172.16.100.171'
redis_hosts = {'fs-1': '172.16.100.170', 'fs-2': '172.16.100.45', 'fs-3': '172.16.100.220', 'fs-4': '172.16.100.171'}

esl_host = '172.16.100.73'

redis_port = 22121
redis_db = 0

# esl connect param:
ESL_PORT = '8021'

# mysql connect param:
SELECT_LIMIT = 100
db_host = "172.16.100.224"
db_port = 3306
db_user = "freeswitch"
db_password = "Yqm1pIEj7r6qpwyN"
db_database = "freeswitch"

# other param:
XML_FILE_PATH = "/etc/freeswitch/sip_profiles/external/"
XML_USER_FILE_PATH = '/etc/freeswitch/directory/default/'
XML_CUSTOM_TRUNK_FILE_PATH = '/etc/freeswitch/directory/client_trunk/'
CUSTOM_TRUNK_PREFIX = 'client_trunk_'
BLOCK_SIP_ACCOUNT_PATH = '/etc/freeswitch/directory/blocked_'
UNBLOCK_SIP_ACCOUNT_PATH = '/etc/freeswitch/directory/unblocked/'
root@lpt-fs-main:/etc/freeswitch/tapi#
root@lpt-fs-main:/etc/freeswitch/tapi#
root@lpt-fs-main:/etc/freeswitch/tapi#
root@lpt-fs-main:/etc/freeswitch/tapi#
root@lpt-fs-main:/etc/freeswitch/tapi#
root@lpt-fs-main:/etc/freeswitch/tapi#
root@lpt-fs-main:/etc/freeswitch/tapi#
root@lpt-fs-main:/etc/freeswitch/tapi# cat tapi_function.py
#!flask/bin/python
# coding: utf-8


__author__ = "Leonid Pshennikov"


import os
import ESL
import redis
import logging
import MySQLdb

from lxml import etree as ET

from tapi_config import *
from datetime import datetime


logging.basicConfig(filename=log_path, level=logging.INFO)


# Функция проверяет существует ли данный clid в clid_key_member
#(проверяем обрабатывали мы уже подобный клид или нет, если да то отправляем вызов на нужную ноду)
def check_exist_clid_in_key_member(clid):
    return execute_redis_command('SISMEMBER', "clid_key_member", clid, host=redis_host, port=redis_port, db=redis_db)


# Функция возвращает по clid адрес ноды из редис (смотрим ключ pair_clid_node_ip-_clid_)
def get_node_ip_from_pair_clid_node_ip(clid):
    return execute_redis_command('GET', "pair_clid_node_ip-" + clid, host=redis_host, port=redis_port, db=redis_db)


# Функция для получения времени сразу в удобном формате
def now():
    return str(datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3])


# Функция которая по clid пытается найти ноду которая обслужила вызов
# clid example:
# cldev-fs_dev-1-1594637706-3239600
# cldev-out-fs_dev-1-1594711916-5521789
def get_node_ip_from_clid(clid, dict_nodes):
    list_clid = clid.split("-")
    node_name = list_clid[1] + "-" + list_clid[2]
    node_ip = dict_nodes.get(node_name)

    if node_ip is None:
        node_name = list_clid[2] + "-" + list_clid[3]
        node_ip = dict_nodes.get(node_name)

    return node_ip


# Функция которая по call_id пытается найти ноду которая обслужила вызов (используется запрос в редис)
def get_node_ip_from_call_id_redis(call_id, dict_nodes):
    node_name = execute_redis_command('GET', "node_" + (call_id), host=redis_host, port=redis_port, db=redis_db)
    return dict_nodes.get(node_name)


def execute_redis_command(command, *args, **kwargs):
    connection = redis.Connection(**kwargs)
    try:
        connection.connect()
        connection.send_command(command, *args)
        response = connection.read_response()
        if command in redis.Redis.RESPONSE_CALLBACKS:
            return redis.Redis.RESPONSE_CALLBACKS[command](response)
        return response

    finally:
        connection.disconnect()
        del connection


def execute_esl_command(cmd, ip):
    con = ESL.ESLconnection(ip, ESL_PORT, 'ClueCon')

    if not con.connected():
        logging.info("execute_esl_command | {} | {} | can't connect to esl".format(
            now(), ip)
        )
        return '-1'
    #        sys.exit(2)

    e = con.bgapi(cmd)

    logging.info("execute_esl_command | {} | {} | e: {}".format(
        now(), ip, e)
    )

    if e:
        logging.info("execute_esl_command | {} | {} | request have sent, request body: {}".format(
            now(), ip, cmd)
        )
        logging.info("execute_esl_command | {} | {} | e.getBody(): {}".format(
            now(), ip, e.getBody())
        )
        return e.getBody()
    else:
        logging.info("execute_esl_command | {} | {} | request haven't sent".format(
            now(), ip)
        )


def execute_esl_command_slowly(cmd, ip):
    con = ESL.ESLconnection(ip, ESL_PORT, 'ClueCon')

    if not con.connected():
        logging.info("execute_esl_command | {} | {} | can't connect to esl".format(
            now(), ip)
        )
        return '-1'
    #        sys.exit(2)

    e = con.api(cmd)

    logging.info("execute_esl_command | {} | {} | e: {}".format(
        now(), ip, e)
    )

    # if e:
    #     return e.getBody()

    if e:
        logging.info("execute_esl_command | {} | {} | request have sent, request body: {}".format(
            now(), ip, cmd)
        )
        logging.info("execute_esl_command | {} | {} | e.getBody(): {}".format(
            now(), ip, e.getBody())
        )
        return e.getBody()
    else:
        logging.info("execute_esl_command | {} | {} | request haven't sent".format(
            now(), ip)
        )


def create_xml_file_for_custom_sip_user_trunk(proxy, port, username, password, path, name):
    root = ET.Element('include')
    user = ET.SubElement(root, 'user', id=name)
    gateways = ET.SubElement(user, 'gateways')
    gateway = ET.SubElement(gateways, 'gateway', name=name)

    ET.SubElement(gateway, 'param', name=u'username', value=username)
    ET.SubElement(gateway, 'param', name=u'password', value=password)
    ET.SubElement(gateway, 'param', name=u'realm', value=proxy)
    ET.SubElement(gateway, 'param', name=u'from-user', value=username)
    ET.SubElement(gateway, 'param', name=u'from-domain', value=proxy)
    ET.SubElement(gateway, 'param', name=u'proxy', value=proxy)
    ET.SubElement(gateway, 'param', name=u'outbound-proxy', value=proxy)
    ET.SubElement(gateway, 'param', name=u'extension', value=username)

    tree = ET.ElementTree(root)
    tree.write(path + name + '.xml', pretty_print=True, encoding="utf-8")


# !!! Функционал не реализован до конца, необходимо доработать!
def create_xml_file_for_custom_trunk(trunk_id, proxy, port, flag_auth, username, password, xml_file_path, file_name):
    root = ET.Element('include')
    gateway = ET.SubElement(root, 'gateway', name=trunk_id)

    ET.SubElement(gateway, 'param', name=u'proxy', value=proxy + ":" + port)

    if flag_auth == "true":
        ET.SubElement(gateway, 'param', name=u'register', value="true")
        ET.SubElement(gateway, 'param', name=u'username', value=username)
        ET.SubElement(gateway, 'param', name=u'password', value=password)
    else:
        ET.SubElement(gateway, 'param', name=u'register', value="false")
        ET.SubElement(gateway, 'param', name=u'username', value="not-used")
        ET.SubElement(gateway, 'param', name=u'password', value="not-used")

    ET.SubElement(gateway, 'param', name=u'caller-id-in-from', value="true")
    ET.SubElement(gateway, 'param', name=u'outbound-proxy', value=proxy + ":" + port)

    tree = ET.ElementTree(root)
    tree.write(xml_file_path + str(file_name) + '.xml', pretty_print=True, encoding="utf-8")


def delete_xml_file(path, name, request_id):
    try:
        os.remove(path + name + '.xml')
    except:
        print("delete_xml_file | {} | {} | Something went wrong".format(request_id, now()))
        print("delete_xml_file | {} | {} | "
              "can't remove file {}".format(request_id, now(), path + name + ".xml"))
        logging.info("delete_xml_file | {} | {} | "
                     "can't remove file {}".format(request_id, now(), path + name + ".xml"))
    else:
        print("delete_xml_file | {} | {} | "
              "remove file ".format(request_id, now(), path + name + ".xml"))
        logging.info("delete_xml_file | {} | {} | "
                     "remove file {}".format(request_id, now(), path + name + ".xml"))


def exist_trunk_ip(unique_request_id, trunk_ip):
    logging.info('{} | {} | exist_trunk_ip'.format(now(), unique_request_id))

    method_name = 'func: exist_trunk_ip'
    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')

    logging.info('{} | {} | {} | connected'.format(method_name, now(), unique_request_id))

    x = conn.cursor()
    try:
#        sql_select_request_by_id = 'select id from client_trunk where proxy = {};'.format(trunk_ip)
        sql_select_request_by_id = "select id from client_trunk where proxy = '{}';".format(trunk_ip)

        print('{} | {} | {} | '
              'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))
        logging.info('{} | {} | {} | '
                     'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))

        x.execute(sql_select_request_by_id)
        sql_select_result = x.fetchone()
        print('{} | {} | {} | sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))
        logging.info('{} | {} | {} | '
                     'sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))

        conn.commit()

        if sql_select_result is None:
            print("{} | {} | {} | trunk_ip: {} not found".format(method_name, now(), unique_request_id, trunk_id))
            logging.info("{} | {} | {} | trunk_ip: {} not found".format(method_name, now(), unique_request_id, trunk_id))

            conn.close()
            return True

    except (IOError, Exception) as e:
        print("{} | {} | {} | some except: {}".format(method_name, now(), unique_request_id, e))
        logging.info("{} | {} | {} | some except: {}".format(method_name, now(), unique_request_id, e))

        conn.rollback()
        conn.close()
        return True

    conn.close()
    return False


def exist_trunk_id(unique_request_id, trunk_id):
    logging.info('{} | {} | exist_trunk_id'.format(now(), unique_request_id))

    method_name = 'func: exist_trunk_id'
    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')

    logging.info('{} | {} | {} | connected'.format(method_name, now(), unique_request_id))

    x = conn.cursor()
    try:
        sql_select_request_by_id = 'select id from client_trunk where id = {};'.format(trunk_id)

        print('{} | {} | {} | '
              'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))
        logging.info('{} | {} | {} | '
                     'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))

        x.execute(sql_select_request_by_id)
        sql_select_result = x.fetchone()
        print('{} | {} | {} | sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))
        logging.info('{} | {} | {} | '
                     'sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))

        conn.commit()

        if sql_select_result is None:
            print("{} | {} | {} | trunk_id: {} not found".format(method_name, now(), unique_request_id, trunk_id))
            logging.info("{} | {} | {} | trunk_id: {} not found".format(method_name, now(), unique_request_id, trunk_id))

            conn.close()
            return False

    except (IOError, Exception) as e:
        print("{} | {} | {} | some except: {}".format(method_name, now(), unique_request_id, e))
        logging.info("{} | {} | {} | some except: {}".format(method_name, now(), unique_request_id, e))

        conn.rollback()
        conn.close()
        return False

    conn.close()
    return True

def exist_sip_account_id(unique_request_id, account_id):
    method_name = 'func: exist_sip_account_id'
    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')
    x = conn.cursor()
    try:
        sql_select_request_by_id = 'select id from ext_sip_accounts where id = {};'.format(account_id)

        print('{} | {} | {} | '
              'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))
        logging.info('{} | {} | {} | '
                     'sql_select_request: {}'.format(method_name, now(), unique_request_id, sql_select_request_by_id))

        x.execute(sql_select_request_by_id)
        sql_select_result = x.fetchone()
        print('{} | {} | {} | sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))
        logging.info('{} | {} | {} | '
                     'sql_select_result: {}'.format(method_name, now(), unique_request_id, sql_select_result))

        conn.commit()

        if sql_select_result is None:
            print("{} | {} | {} | sip_account_id: {} "
                  "not found".format(method_name, now(), unique_request_id, account_id))
            logging.info("{} | {} | {} | sip_account_id: "
                         "{} not found".format(method_name, now(), unique_request_id, account_id))

            conn.close()
            return False

    except (IOError, Exception) as e:
        print("{} | {} | {} | some except: {}".format(method_name, now(), unique_request_id, e))
        logging.info("{} | {} | {} | some except: {}".format(method_name, now(), unique_request_id, e))

        conn.rollback()
        conn.close()
        return False

    conn.close()
    return True


def parse_esl_status_response(unique_request_id, response):
    method_name = 'parse_esl_status_resposce'
    state = 'Parsing_Error'
    for s in response.split('\n'):
        split_string = s.split()
        try:
            if split_string[0] == 'State':
                state = split_string[1]
                print("{} | {} | {} | State: {}".format(method_name, now(), unique_request_id, state))
                logging.info("{} | {} | {} | State: {}".format(method_name, now(), unique_request_id, state))

        except IndexError:
            print("{} | {} | {} | IndexError".format(method_name, now(), unique_request_id))
            logging.info("{} | {} | {} | IndexError".format(method_name, now(), unique_request_id))

    return state

def check_path(unique_request_id, path):
    if not os.path.exists(path):
        logging.debug('{} | {} | make path: {}'.format(now(), unique_request_id, path))
        os.makedirs(path)
    else:
        logging.info('{} | {} | path: {} - exists!'.format(now(), unique_request_id, path))


def unblock_sip_account(unique_request_id, sip_account):
    logging.info('{} | {} | exist_trunk_id'.format(now(), unique_request_id))

    method_name = 'func: unblock_sip_account'
    conn = MySQLdb.connect(host=db_host, port=db_port, user=db_user, passwd=db_password, db=db_database, charset='utf8')

    logging.info('{} | {} | {} | connected'.format(method_name, now(), unique_request_id))

    x = conn.cursor()
    try:
        sql_update = 'update ext_sip_accounts set is_blocked={} where username={};'.format('0', sip_account)

        print('{} | {} | {} | sql_update: {}'.format(method_name, now(), unique_request_id, sql_update))
        logging.info('{} | {} | {} | sql_update: {}'.format(method_name, now(), unique_request_id, sql_update))

        x.execute(sql_update)
        conn.commit()

    except (IOError, Exception) as e:
        print("{} | {} | {} | some except: {}".format(method_name, now(), unique_request_id, e))
        logging.info("{} | {} | {} | some except: {}".format(method_name, now(), unique_request_id, e))

        conn.rollback()
        conn.close()
        return False

    conn.close()
    return True



def validate_date(unique_request_id, date):
    method_name = 'validate_date'
    if len(date.split('-')) == 3:
        try:
            datetime.strptime(date, '%Y-%m-%d')
            print("{} | {} | {} | date: {} validated".format(method_name, now(), unique_request_id, date))
            logging.info("{} | {} | {} | date: {} validated".format(method_name, now(), unique_request_id, date))
            return False

        except Exception:
            print("{} | {} | {} | date: {} didn't validate".format(method_name, now(), unique_request_id, date))
            logging.info("{} | {} | {} | date: {} didn'tvalidate".format(method_name, now(), unique_request_id, date))
            return True

    print("{} | {} | {} | date: {} has wrong length".format(method_name, now(), unique_request_id, date))
    logging.info("{} | {} | {} | date: {} has wrong length".format(method_name, now(), unique_request_id, date))
    return True

