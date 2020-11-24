#!/usr/bin/python3

import json
import sched, time
import subprocess
import uuid

class ArmClientError(Exception):
    """
    Indicates a problem with the armclient REST API call.
    """
    pass

class ArmClient(object):
    """
    The ResourceOperations class provides methods to perform crud operations to a specific endpoint
    """

    def __init__(self):
        self._baseUrl = 'https://management.azure.com'
        self._armclient = 'armclient.exe'

    @property
    def baseUrl(self):
        return self._baseUrl

    @property
    def apiVersion(self):
        return self._apiVersion

    def get_resource_group_body(self, location):
        body = { "location": location}
        return json.dumps(body)

    def cmd_wrapper(self, cmd):
        print('Running subprocess with command %s' % cmd )
        try:
            output = subprocess.check_output(cmd, subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as e:
            print('cmd_wrapper failed for command "%s" and gave '
                'return code "%s" and output "%s"'
                % (cmd, e.returncode, e.output))
            raise

        return output.strip()

    def wait_for_deployment_complete(resource_id, api_version):
        result = self.get_resource(resource_id, api_version)



    def create_resource_group(self, subscriptionId, resource_group_name, location):
        resource_group = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resource_group_name
        resource_json = self.get_resource_group_body(location)
        rg = self.put_resource(resource_group, resource_json, '2019-10-01')

    def deploy_template(self, subscriptionId, deployment_name, resource_group_name, location, template_file, template_params=''):
        self.create_resource_group(subscriptionId, resource_group_name, location)
        resourceId = '/subscriptions/' + subscriptionId + '/resourceGroups/' + resource_group_name + '/providers/Microsoft.Resources/deployments/{0}'.format(deployment_name)

        if template_file.startswith('/windir/c'):
            template_file = template_file[len('/windir/c'):]
        url = self.baseUrl + resourceId + '?api-version=2019-10-01'
        headers = ' ' + '-h "Referer: ' + url + '"'
        cmd = self._armclient + " put " + url + " " + "@" + template_file + ' ' + headers
        output = self.cmd_wrapper(cmd)

        result = output.decode("utf-8")
        try:
            # if the call succeeded, result should be json data
            json.loads(result)
        except:
            # incase of failure return string as error
            raise ArmClientError(result)

        self.wait_for_deployment_complete(resourceId, '2019-10-01')

        return result 

    def put_resource(self, resourceId, resourceJson, apiVersion):
        url = self.baseUrl + resourceId + '?api-version=' + apiVersion
        headers = ' ' + '-h "Referer: ' + url + '"'
        cmd = self._armclient + " put " + url + " " + "'" +  resourceJson + "'" + headers
        output = self.cmd_wrapper(cmd)

        result = output.decode("utf-8")
        try:
            # if the call succeeded, result should be json data
            json.loads(result)
        except:
            # incase of failure return string as error
            raise ArmClientError(result)

        return result 


    def get_resource(self, resourceId, apiVersion):
        url = self.baseUrl + resourceId + '?api-version=' + apiVersion
        headers = ' ' + '-h "Referer: ' + url + '"'
        cmd = self._armclient + ' get ' + url + headers
        output = self.cmd_wrapper(cmd)

        result = output.decode("utf-8")
        try:
            # if the call succeeded, result should be json data
            json.loads(result)
        except:
            # incase of failure return string as error
            raise ArmClientError(result)

        return result

    def delete_resource(self, resourceId, apiVersion):
        url = self.baseUrl + resourceId + '?api-version=' + apiVersion
        headers = ' ' + '-h "Referer: ' + url + '"'
        cmd = self._armclient + ' delete ' + url + headers
        self.cmd_wrapper(cmd)

def main():
    cl = ArmClient()
    cl.get('/subscriptions/f6cb8187-b300-4c2d-9b23-c00e7e98d799/resourceGroups/checkpointTestRG')

if __name__ == '__main__':
    main()
