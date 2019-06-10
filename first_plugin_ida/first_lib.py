# -------------------------------------------------------------------------------
#
#   Function Identification and Recovery Signature Tool (FIRST) python library
#
#   Copyright (C) 2019 Cisco Talos Security Intelligence and Research Group
#
#   Authors: Angel M. Villegas, Xabier Ugarte-Pedrero
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   Requirements
#   ------------
#   Requests (docs.python-requests.org/)
#
# -------------------------------------------------------------------------------

#   Python Modules
import re
import json

import logging
from base64 import b64encode

#   Third Party Python Modules
required_modules_loaded = True
try:
    import requests
except ImportError:
    required_modules_loaded &= False
    print
    'FIRST library requires Python module requests'

VALID_ARCHITECTURES = ['intel32', 'intel64', 'arm32', 'mips']

def is_valid_architecture(arch):
    return ((isinstance(arch, str) or isinstance(arch, unicode)) and (arch in VALID_ARCHITECTURES))

#   Logging configuration
#   ---------------------

logger = logging.getLogger('FIRST')

# Remove existing handlers
while len(logger.handlers) > 0:
    h = logger.handlers[0]
    logger.removeHandler(h)

#   Helper class to contain metadata
#   --------------------------------

class FunctionMetadata(object):
    '''Class to contain a FIRST match and its data.

    FIRST metadata container, it encapsulates the data received from the
    FIRST server.

    Args:
        data (:obj:`dict`): Dictionary with the following key values set:
            name, prototype, creator, id, comment, rank
        address (:obj:`int`): The VA associated with the function the
            instance refers to.
        engine_info (:obj:`dict`): Dictionary with engine names mapping to
            the engine's description.

    Raises:
        TypeError: If data is not a :obj:`dict` or does not have the
            required keys.
    '''

    def __init__(self, data, address=None, engine_info=None):
        error_str = 'Cannot encapsulate server metadata'
        required = ['name', 'prototype', 'creator', 'id', 'comment', 'rank']

        if (dict != type(data) or not set(required).issubset(data.keys())):
            raise TypeError(error_str)

        self.__data = data
        self.__address = address
        self.__engines = engine_info

        self.__id = data['id']
        self.__name = data['name']
        self.__rank = data['rank']
        self.__creator = data['creator']
        self.__comment = data['comment']
        self.__prototype = data['prototype']
        self.__similarity = 0

        if 'similarity' in data:
            self.__similarity = data['similarity']

    def __eq__(self, other):
        return ((self.name == other.name)
                and (self.prototype == other.prototype)
                and (self.comment == other.comment)
                and (self.id == other.id)
                and (self.creator == other.created))

    def get_raw_data(self):
        return {'data': self.__data, 'address': self.__address, 'engines': self.__engines}

    @property
    def address(self):
        ''':obj:`int`: The virtual address associated with the function.'''
        return self.__address

    @property
    def name(self):
        ''':obj:`str`: The name of the function'''
        return self.__name

    @property
    def prototype(self):
        ''':obj:`str`: The prototype of the function'''
        if not self.__prototype:
            return ''

        return self.__prototype

    @property
    def comment(self):
        ''':obj:`str`: The comment associated with the function.'''
        if not self.__comment:
            return ''

        return self.__comment

    @property
    def creator(self):
        ''':obj:`str`: The handle of the annotation creator.'''
        return self.__creator

    @property
    def id(self):
        ''':obj:`str`: The FIRSTCore ID associated with this metadata.'''
        return self.__id

    @property
    def rank(self):
        ''':obj:`int`: The number of unqiue applies of this metadata.'''
        return self.__rank

    @property
    def similarity(self):
        ''':obj:`float`: The percentage of similarity between this function
            and the original queried for function. This value can be very
            rough estimate depending on the engine.'''
        return self.__similarity

    @property
    def engine_info(self):
        ''':obj:`dict`: The mapping from engine name to its description.'''
        if not self.__engines:
            return {}

        return self.__engines

class FIRSTServer(object):
    
    '''Encapsulate interacting with the FIRSTCore server's REST API.

    Note:
        Using functions ``set_protocol``, ``set_server``, and ``set_port``
        do not update the configuration details, just the server instance
        represented with this class.


    Attributes:
        urn (:obj:`str`): URL format string.
        paths (:obj:`dict`): Mapping between operations and FIRSTCore URI path
            format strings.
        MAX_CHUNK (:obj:`int`): The maximum number of entries sent to the
            server. Default: 20

            Note:
                The FIRSTCore server can set the max number of entries received.
                If this value is greater than the server's then the server
                will not perform the operation.

        Args:
            config (:obj:`dict` or :obj: 'json'): FIRST Server configuration information.
                {
                    'server' (:obj: `str`) The server domain or IP address.
                    'proto' (:obj: `str`) The protocol to use ('http' or 'https')
                    'port': (:obj: `int`) The port to use (e.g.: 80, 443)
                    'verify' (:obj: `bool`) For HTTPS, verify the certificate or skip verification
                    'api_key' (:obj: `str`) The API key to use for authentication
                }
            h_md5 (:obj:`str`): The MD5 of the sample.
            crc32 (:obj:`int`): The CRC32 of the sample.
            h_sha1 (:obj:`str`, optional): The SHA1 of the sample.
            h_sha256 (:obj:`str`, optional): The SHA256 of the sample.

    '''
    MAX_CHUNK = 20
    urn = '{0.protocol}://{0.server}:{0.port}/{1}'
    paths = {
        #   Test Connection URL
        'test': 'api/test_connection/{0[api_key]}',

        'checkin': 'api/sample/checkin/{0[api_key]}',

        #   Metadata URLs
        'add': 'api/metadata/add/{0[api_key]}',
        'history': 'api/metadata/history/{0[api_key]}',
        'applied': 'api/metadata/applied/{0[api_key]}',
        'unapplied': 'api/metadata/unapplied/{0[api_key]}',
        'delete': 'api/metadata/delete/{0[api_key]}/{0[id]}',
        'created': 'api/metadata/created/{0[api_key]}/{0[page]}',
        'get': 'api/metadata/get/{0[api_key]}',

        #   Scan URLs
        'scan': 'api/metadata/scan/{0[api_key]}',
    }

    def __init__(self, config, h_md5, crc32, h_sha1=None, h_sha256=None):
        self.error_log = []
        self.checkedin = False
        self.binary_info = {'md5': h_md5, 'crc32': crc32,
                            'sha1': h_sha1, 'sha256': h_sha256}

        self.server, self.protocol = [None] * 2
        self.port, self.verify, self.api_key = [None] * 3

        if isinstance(config, dict) or isinstance(config, json):
            self.server = config['server']
            self.protocol = config['proto']
            self.port = config['port']
            self.verify = config['verify']
            self.api_key = config['api_key']

    def set_port(self, port):
        '''Overrides the FIRSTCore server port set in the configuration.

        Args:
            port (:obj:`int`): The FIRSTCore server port.
        '''
        self.checkedin = False
        self.port = port

    def set_protocol(self, protocol):
        '''Overrides the FIRSTCore server protocol set in the configuration.

        Args:
            protocol (:obj:`int`): The FIRSTCore server protocol.
        '''
        self.checkedin = False
        self.protocol = protocol

    def set_server(self, server):
        '''Overrides the FIRSTCore server set in the configuration.

        Args:
            port (:obj:`int`): The FIRSTCore server.
        '''
        self.checkedin = False
        self.server = server

    def checkin(self, action):
        '''Checks in with FIRSTCore server to ensure annotations can be added.

        This function must be called before any annotations are added to
        FIRSTCore. This function allows the FIRSTCore server to setup information
        about the sample, thereby allowing functions to be associated with
        the sample. This only needs to be called once and is attempted
        before the first user selected operation.

        This operation is not done if the operation to be performed is to
        test the connection to the server.

        Args:
            action (:obj:`str`): The FIRSTCore operation to be performed
        '''
        if self.checkedin or action == 'test':
            return

        self.checkedin = True

        response = self._sendp('checkin', self.binary_info)
        if (not response
                or (('failed' in response) and response['failed'])
                or (('checkin' in response) and not response['checkin'])):
            #   Try to check in again with the next sever communication
            self.checkedin = False

        return self.checkedin

    def _sendp(self, action, params={}, raw=False):
        self.checkin(action)

        if action not in self.paths:
            return None

        #   Ensure all None values are converted to empty strings
        for key in params:
            if params[key] is None:
                params[key] = ''

        url = self.urn.format(self, self.paths[action])
        try:
            response = requests.post(url.format(self._user()),
                                     data=params,
                                     verify=self.verify)

            if raw:
                return response

        except requests.exceptions.ConnectionError as e:
            title = 'Cannot connect to FIRSTCore'
            msg = ('Unable to connect to FIRSTCore server at {0}\n'
                   'Retry operation').format(self.server)
            logger.error(msg)
            raise ConnectionError(title)

        except requests.exceptions.Timeout as e:
            title = 'Cannot connect to FIRSTCore'
            msg = ('Unable to connect to FIRSTCore server at {0}. '
                   'Connection timed out.').format(self.server)
            logger.error(msg)
            return

        if 'status_code' not in dir(response):
            return None
        elif 200 != response.status_code:
            return None

        response = self.to_json(response)

        return response

    def _sendg(self, action, params={}, raw=False):
        self.checkin(action)

        if action not in self.paths:
            return None

        #   Ensure all None values are converted to empty strings
        for key in params:
            if params[key] is None:
                params[key] = ''

        params.update(self._user())

        url = self.urn.format(self, self.paths[action])
        try:
            response = requests.get(url.format(params),
                                    verify=self.verify)

            if raw:
                return response

        except requests.exceptions.ConnectionError as e:
            title = 'Cannot connect to FIRSTCore'
            msg = ('Unable to connect to FIRSTCore server at {0}\n'
                   'Retry operation').format(self.server)
            logger.error(msg)
            raise ConnectionError(title)

        except requests.exceptions.Timeout as e:
            title = 'Cannot connect to FIRSTCore'
            msg = ('Unable to connect to FIRSTCore server at {0}. '
                   'Connection timed out.').format(self.server)
            logger.error(msg)
            return

        if 'status_code' not in dir(response):
            return None
        elif 200 != response.status_code:
            return None

        response = self.to_json(response)

        return response

    def to_json(self, response):
        '''Converts Requests' response object to json.

        Args:
            response (:obj:`requests.models.Response`): A request response.

        Returns:
            dict: JSON data or empty dictionary.
        '''
        try:
            return response.json()
        except:
            return {}

    def _user(self):
        return {'api_key': self.api_key}

    def _min_info(self):
        return {'md5': self.binary_info['md5'],
                'crc32': self.binary_info['crc32']}

    #   Test connection URL
    def test_connection(self):
        '''Interacts with server to see if there is a valid connection.

        This is a short operation and is a blocking call.

        Returns:
            bool: True if connection can be made and FIRSTCore returns a
                success message. False otherwise.
        '''
        if not self.api_key:
            return False

        try:
            data = self._sendg('test', {'api_key': self.api_key})
        except ConnectionError as e:
            data = None

        return data and ('status' in data) and ('connected' == data['status'])

    #   Signature URLS
    def add(self, metadata, architecture, data_callback=None, complete_callback=None, should_stop=None):
        '''Adds function metadata to FIRST.

        This is a long operation, thus it has the option of providing a
        ``data_callback``, ``complete_callback``, and ``should_stop`` arguments. The first
        two arguments are functions that will be called with the newly returned
        data and when the whole operation is completed, respectively. Both
        functions should follow their respective prototypes:
        ``def data_callback(sub_results)`` and ``def complete_callback(results)``.
        The ``should_stop`` function is called on every iteration of the loop that 
        queries data from the server. If this function is called asynchronously (e.g., 
        in a separate thread), it is possible to use the return value of should_stop()
        to stop the execution of the function and return prematurely.

        Args:
            metadata (:obj:`list` of :obj:`dict`: The metadata to be added to FIRST.
                metadata (dict): Dictionary of function metadata
                    {
                        address
                        signature
                        name
                        prototype
                        comment
                        apis
                        id
                    }
            architecture (:obj: 'str') string that's either ['intel32', 'intel64', 'arm32', 'mips']
            data_callback (:obj:`data_callback_prototype`, optional):
                A function to call when data is receieved from the server.
            complete_callback (:obj:`complete_callback_prototype`, optional):
                A function to call when the whole long operation completes.
            should_stop (:obj:`should_stop_prototype`, optional):
                A function called by this function before every query to the server, 
                to check if the process should be stopped.


        Returns:
            list of dict: JSON data returned from the server. None on failure.
        '''

        results = {}

        if not isinstance(metadata, list):
            metadata = [metadata]

        if False in [isinstance(m, dict) for m in metadata]:
            raise TypeError("The metadata parameter should be of type 'dict' or list('dict')")

        if not is_valid_architecture(architecture):
            raise ValueError("The architecture must be one of the following: %s" % str(VALID_ARCHITECTURES))

        for i in range(0, len(metadata), self.MAX_CHUNK):
            params = self._min_info()
            data = {}
            for m in metadata[i:i + self.MAX_CHUNK]:
                data[m['address']] = {'architecture': architecture,
                                       'opcodes': b64encode(m['signature']).decode('utf-8'),
                                       'name': m['name'],
                                       'prototype': m['prototype'],
                                       'comment': m['comment'],
                                       'apis': m['apis'],
                                       'id': m.get('id', None)}

            params['functions'] = json.dumps(data)
            try:
                response = self._sendp('add', params)
            except ConnectionError as e:
                if complete_callback:
                    complete_callback(results)
                return results

            if response and 'failed' in response and not response['failed'] and 'results' in response:
                sub_results = {}
                for addr in response['results']:
                    sub_results[int(addr)] = response['results'][addr]
                # Merge results into thread results
                for address in sub_results:
                    if address not in results:
                        results[address] = sub_results[address]
                    else:
                        results[address].extend(sub_results[address])

                if data_callback:
                    data_callback(sub_results)

            if should_stop and should_stop():
                break

        if complete_callback:
            complete_callback(results)

        return results

    def history(self, metadata):
        '''Gets annotation history from FIRSTCore.

        This is a short operation and is a blocking call.

        Args:
            metadata (:obj:`dict`: The metadata to be added to FIRST
                metadata (dict): Dictionary of function metadata (type to be flled in later)
                    {
                        address
                        signature
                        name
                        prototype
                        comment
                        apis
                        id
                    }

        Returns:
            dict: JSON data returned from server. None on failure.
        '''
        FIRSTId = metadata['id']

        if not re.match('^[\da-f]{26}$', FIRSTId):
            return None

        data = {'opcodes': b64encode(metadata['signature']).decode('utf-8'),
                'name': metadata['name'],
                'prototype': metadata['prototype'],
                'comment': metadata['comment'],
                'apis': metadata['apis'],
                'id': metadata['id']}

        params = {}
        params['metadata'] = json.dumps(data)

        try:
            response = self._sendp('history', params)
        except ConnectionError as e:
            return None

        return response

    def applied(self, metadata_id):
        '''Sets a FIRSTCore annotation as applied to this sample.

        This is a short operation and is a blocking call.

        Args:
            metadata_id (:obj:`str`): The FIRSTCore annotation ID.

        Returns:
            dict: JSON data returned from the server. None on failure.
        '''
        params = self._min_info()
        params['id'] = metadata_id

        try:
            response = self._sendp('applied', params)
        except ConnectionError as e:
            return None

        return response

    def unapplied(self, metadata_id):
        '''Sets a FIRSTCore annotation as unapplied to this sample.

        This is a short operation and is a blocking call.

        Args:
            metadata_id (:obj:`str`): The FIRSTCore annotation ID.

        Returns:
            dict: JSON data returned from the server. None on failure.
        '''
        params = self._min_info()
        params['id'] = metadata_id

        try:
            response = self._sendp('unapplied', params)
        except ConnectionError as e:
            return None

        return response

    def delete(self, metadata_id):
        '''Deletes a FIRSTCore annotation created by the user.

        This is a short operation and is a blocking call.

        Args:
            metadata_id (:obj:`str`): The FIRSTCore annotation ID.

        Returns:
            dict: JSON data returned from the server. None on failure.
        '''
        params = {'id': metadata_id}

        try:
            response = self._sendg('delete', params)
        except ConnectionError as e:
            print(str(e))
            return None

        return response


    def created(self, data_callback=None, complete_callback=None, should_stop=None):
        '''Retrieves FIRSTCore annotations the user has created.

        This is a long operation, thus it has the option of providing a
        ``data_callback``, ``complete_callback``, and ``should_stop`` arguments. The first
        two arguments are functions that will be called with the newly returned
        data and when the whole operation is completed, respectively. Both
        functions should follow their respective prototypes:
        ``def data_callback(sub_results)`` and ``def complete_callback(results)``.
        The ``should_stop`` function is called on every iteration of the loop that 
        queries data from the server. If this function is called asynchronously (e.g., 
        in a separate thread), it is possible to use the return value of should_stop()
        to stop the execution of the function and return prematurely.

        Args:
            data_callback (:obj:`data_callback_prototype`, optional):
                A function to call when data is receieved from the server.
            complete_callback (:obj:`complete_callback_prototype`, optional):
                A function to call when the whole long operation completes.
            should_stop (:obj:`should_stop_prototype`, optional):
                A function called by this function before every query to the server, 
                to check if the process should be stopped.

        Returns:
            list: A list of FunctionMetadata instances
        '''
        results = []

        page = 1
        total_pages = 0
        first_time = True
        while (first_time
               or ((page <= total_pages) and (not (should_stop and should_stop())))):
            if first_time:
                first_time = False

            try:
                response = self._sendg('created', {'page': page})
            except ConnectionError as e:
                if complete_callback:
                    complete_callback(results)
                return results

            if not response:
                continue

            if 'pages' in response:
                total_pages = response['pages']

            #   Print out page data very 10 percent
            ten_percent = total_pages / 10.0
            if (not ten_percent) or (0 == (page % ten_percent)):
                logger.debug('{} out of {} pages\n'.format(page, total_pages))

            if ('results' in response) and response['results']:
                metadata = response['results']
                data = [FunctionMetadata(x, x['id']) for x in metadata]
                results.extend(data)
                if data_callback:
                    data_callback(data)
            page += 1

        if complete_callback:
            complete_callback(results)
        return results

    def get(self, metadata, data_callback=None, complete_callback=None, should_stop=None):
        '''Retrieves FIRSTCore annotations the user has created.

        This is a long operation, thus it has the option of providing a
        ``data_callback``, ``complete_callback``, and ``should_stop`` arguments. The first
        two arguments are functions that will be called with the newly returned
        data and when the whole operation is completed, respectively. Both
        functions should follow their respective prototypes:
        ``def data_callback(sub_results)`` and ``def complete_callback(results)``.
        The ``should_stop`` function is called on every iteration of the loop that 
        queries data from the server. If this function is called asynchronously (e.g., 
        in a separate thread), it is possible to use the return value of should_stop()
        to stop the execution of the function and return prematurely.


        Args:
            metadata (:obj:`list` of :str:): The metadata ids to
                be retrieved from FIRST.
            data_callback (:obj:`data_callback_prototype`, optional):
                A function to call when data is receieved from the server.
            complete_callback (:obj:`complete_callback_prototype`, optional):
                A function to call when the whole long operation completes.
            should_stop (:obj:`should_stop_prototype`, optional):
                A function called by this function before every query to the server, 
                to check if the process should be stopped.
        Returns:
            dict: JSON data returned from the server. None on failure.
        '''

        results = {}

        if not isinstance(metadata, list):
            metadata = [metadata]

        if False in [(isinstance(m, str) or isinstance(m, unicode)) for m in metadata]:
            raise TypeError("The metadata parameter should be of type 'str' or list('str')")

        for i in range(0, len(metadata), self.MAX_CHUNK):
            if should_stop and should_stop():
                break

            data = [m for m in metadata[i:i + self.MAX_CHUNK]]

            try:
                response = self._sendp('get', {'metadata': json.dumps(data)})
            except ConnectionError as e:
                if complete_callback:
                    complete_callback(results)
                return results

            if (not response or ('results' not in response)
                    or (dict != type(response['results']))
                    or (not len(response['results']))):
                continue

            sub_results = {}
            for metadata_id, details in response['results'].items():
                sub_results[metadata_id] = FunctionMetadata(details)

            if 0 < len(sub_results):
                for metadata_id in sub_results:
                    results[metadata_id] = sub_results[metadata_id]
                if data_callback:
                    data_callback(sub_results)

        if complete_callback:
            complete_callback(results)

        return results

    def scan(self, metadata, architecture, data_callback=None, complete_callback=None, should_stop=None):
        '''Queries FIRSTCore for matches.

        This is a long operation, thus it has the option of providing a
        ``data_callback``, ``complete_callback``, and ``should_stop`` arguments. The first
        two arguments are functions that will be called with the newly returned
        data and when the whole operation is completed, respectively. Both
        functions should follow their respective prototypes:
        ``def data_callback(sub_results)`` and ``def complete_callback(results)``.
        The ``should_stop`` function is called on every iteration of the loop that 
        queries data from the server. If this function is called asynchronously (e.g., 
        in a separate thread), it is possible to use the return value of should_stop()
        to stop the execution of the function and return prematurely.

        Args:
            metadata (:obj:`list` of :obj:`dict`: The metadata to be scanned on FIRST.
                metadata (dict): Dictionary of function metadata
                    {
                        address (int)
                        signature (:obj:`str` or :obj:`bytes`)
                        apis (:obj:`list` of :obj:`str`)
                    }
            architecture (:obj: 'str', valid architecture string. Valid values are: intel32, intel64, arm32, mips
            data_callback (:obj:`data_callback_prototype`, optional):
                A function to call when data is receieved from the server.
            complete_callback (:obj:`complete_callback_prototype`, optional):
                A function to call when the whole long operation completes.
            should_stop (:obj:`should_stop_prototype`, optional):
                A function called by this function before every query to the server, 
                to check if the process should be stopped.

        Returns:
            dict: JSON data returned from the server. None on failure.
        '''
        results = {}

        if not isinstance(metadata, list):
            metadata = [metadata]

        if False in [isinstance(m, dict) for m in metadata]:
            raise TypeError("The metadata parameter should be of type 'dict' or list('dict')") 

        if not is_valid_architecture(architecture):
            raise ValueError("The architecture must be one of the following: %s" % str(VALID_ARCHITECTURES))

        subkeys = {'engines', 'matches'}

        for i in range(0, len(metadata), self.MAX_CHUNK):
            # Check if we must stop the loop, used
            # for asynchronous operations
            if should_stop and should_stop():
                break

            params = self._min_info()
            data = {}
            for m in metadata[i:i + self.MAX_CHUNK]:
                signature = m['signature']
                if not signature:
                    continue
                data[m['address']] = {'opcodes': b64encode(m['signature']).decode('utf-8'),
                                   'apis': m['apis'],
                                   'architecture': architecture}

            params['functions'] = json.dumps(data)

            try:
                response = self._sendp('scan', params)
            except ConnectionError as e:
                if complete_callback:
                    complete_callback(results)
                return results

            if (not response or ('results' not in response)
                    or (dict != type(response['results']))
                    or (not subkeys.issubset(response['results'].keys()))
                    or (0 == len(response['results']['matches']))):
                continue

            sub_results = {}
            engine_info = response['results']['engines']
            matches = response['results']['matches']
            for address_str in matches:
                functions = []
                address = int(address_str)

                for match in matches[address_str]:
                    engines = {x: engine_info[x] for x in match['engines']}
                    data = FunctionMetadata(match, address, engines)
                    functions.append(data)

                if len(functions) > 0:
                    sub_results[address] = functions

            if 0 < len(sub_results):
                # Merge sub_results into global results
                for address in sub_results:
                    if address not in results:
                        results[address] = sub_results[address]
                    else:
                        results[address].extend(sub_results[address])
                if data_callback:
                    data_callback(sub_results)

        if complete_callback:
            complete_callback(results)
        return results
