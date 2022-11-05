import sys
import os
import math

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(SCRIPT_DIR))

from halo import config_helper
from halo import halo_api_caller

list_of_groups = []

def test_get_group_servers(group_id):
    config = config_helper.ConfigHelper()
    halo_api_caller_obj = halo_api_caller.HaloAPICaller(config)
    halo_api_caller_obj.authenticate_client()
    group_servers_list = halo_api_caller_obj.get_group_servers(group_id)
    print(group_servers_list[0]['count'])


def test_get_group_childs(group_id, flag):
    config = config_helper.ConfigHelper()
    halo_api_caller_obj = halo_api_caller.HaloAPICaller(config)
    halo_api_caller_obj.authenticate_client()
    if flag == True:
        list_of_groups.append(group_id)
    group_childs_list = halo_api_caller_obj.get_group_childs(group_id)
    group_childs_list_count = group_childs_list[0]['count']
    if(group_childs_list_count > 0):
        for group in group_childs_list[0]['groups']:
            if group['has_children'] == False:
                list_of_groups.append(group['id'])
            else:
                list_of_groups.append(group['id'])
                test_get_group_childs(group['id'], False)

def test_get_all_groups_servers(list_of_group_ids):
    total_servers_list = []
    config = config_helper.ConfigHelper()
    halo_api_caller_obj = halo_api_caller.HaloAPICaller(config)
    halo_api_caller_obj.authenticate_client()
    if(len(list_of_group_ids) > 0):
        for group_id in list_of_group_ids:
            group_servers_list = halo_api_caller_obj.get_group_servers(group_id)
            group_servers_list_data = group_servers_list[0]
            try:
                total_number_of_servers = group_servers_list_data['count']
            except:
                total_number_of_servers = 0
            servers_pages = math.ceil(total_number_of_servers/100)
            for page in range(servers_pages):
                current_page = page+1
                page_group_servers_list = halo_api_caller_obj.get_group_servers_per_page(
                    group_id, current_page)
                servers_list = page_group_servers_list[0]['servers']
                total_servers_list.extend(servers_list)
    return total_servers_list

if __name__ == "__main__":
    test_get_group_childs("67b04036a8c411e9a8b62930f061b45d", True)
    print(len(list_of_groups))
    total_servers_list = test_get_all_groups_servers(list_of_groups)
    print(len(total_servers_list))
    for server in total_servers_list:
        print(server['id'])
