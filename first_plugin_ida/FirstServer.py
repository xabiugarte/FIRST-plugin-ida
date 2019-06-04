# -------------------------------------------------------------------------------
#
#   IDA Pro Plug-in: Function Identification and Recovery Signature Tool (FIRSTCore)
#   Copyright (C) 2016  Angel M. Villegas
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
#   Installation
#   ------------
#   Drag and drop into IDA Pro's plugin folder for IDA Pro 6.9 SP1 and higher
#
# -------------------------------------------------------------------------------

#   Third Party Python Modules
required_modules_loaded = True
try:
    import requests
except ImportError:
    required_modules_loaded &= False
    print
    'FIRSTCore requires Python module requests'

try:
    from requests_kerberos import HTTPKerberosAuth
except ImportError:
    print
    '[1st] Kerberos support is not avaialble'
    HTTPKerberosAuth = None

#   Python Modules
import re
import json
import threading

import logging
from base64 import b64encode

#   Logging configuration
# -------------------------------------------------------------------------------

class FirstServerError(Exception):
    '''FIRSTCore Exception Class'''

    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

logger = logging.getLogger('FIRSTCore')
# Remove existing handlers
while len(logger.handlers) > 0:
    h = logger.handlers[0]
    logger.removeHandler(h)

class MetadataServer(object):
    '''Class to contain a FIRSTCore match and its data.

    FIRSTCore Metadata container, it encapsulates the data received from the
    FIRSTCore server.

    Args:
        data (:obj:`dict`): Dictionary with the following key values set:
            name, prototype, creator, id, comment, rank
        address (:obj:`int`): The VA associated with the function the
            instance refers to.
        engine_info (:obj:`dict`): Dictionary with engine names mapping to
            the engine's description.

    Raises:
        FIRSTCore.FirstServerError: If data is not a :obj:`dict` or does not have the
            required keys.
    '''

    def __init__(self, data, address=None, engine_info=None):
        error_str = 'Cannot encapsulate server metadata'
        required = ['name', 'prototype', 'creator', 'id', 'comment', 'rank']

        if (dict != type(data) or not set(required).issubset(data.keys())):
            raise FirstServerError(error_str)

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

    def get_raw_data(self):
        return {'data': self.__data, 'address': self.__address, 'engines': self.__engines}


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
            config (:obj:`str` or :obj: 'json'): FIRST Server configuration information.
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

    def __init__(self, config, h_md5, crc32, h_sha1=None, h_sha256=None, multithreaded=False):
        self.error_log = []
        self.threads = {}
        self.checkedin = False
        self.binary_info = {'md5': h_md5, 'crc32': crc32,
                            'sha1': h_sha1, 'sha256': h_sha256}

        self.auth, self.server, self.protocol = [None] * 3
        self.port, self.verify, self.api_key = [None] * 3
        self.multithreaded = multithreaded

        if isinstance(config, dict) or isinstance(config, json):
            self.auth = config['auth']
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
            return

    def _sendp(self, action, params={}, raw=False):
        self.checkin(action)

        if action not in self.paths:
            return None

        #   Ensure all None values are converted to empty strings
        for key in params:
            if params[key] is None:
                params[key] = ''

        authentication = None
        if self.auth:
            if not HTTPKerberosAuth:
                logger.debug('[1st] Kerberos module is not loaded\n')
                return

            authentication = HTTPKerberosAuth()

        url = self.urn.format(self, self.paths[action])
        try:
            response = requests.post(url.format(self._user()),
                                     data=params,
                                     verify=self.verify,
                                     auth=authentication)

            if raw:
                return response

        except requests.exceptions.ConnectionError as e:
            title = 'Cannot connect to FIRSTCore'
            msg = ('Unable to connect to FIRSTCore server at {0}\n'
                   'Retry operation').format(self.server)
            logger.error(msg)
            raise FirstServerError('cannot connect')

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

        authentication = None
        if self.auth:
            if not HTTPKerberosAuth:
                logger.debug('[1st] Kerberos module is not loaded\n')
                return

            authentication = HTTPKerberosAuth()

        url = self.urn.format(self, self.paths[action])
        try:
            response = requests.get(url.format(params),
                                    verify=self.verify,
                                    auth=authentication)

            if raw:
                return response

        except requests.exceptions.ConnectionError as e:
            title = 'Cannot connect to FIRSTCore'
            msg = ('Unable to connect to FIRSTCore server at {0}\n'
                   'Retry operation').format(self.server)
            logger.error(msg)
            raise FirstServerError('cannot connect')

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

    def stop_operation(self, server_thread):
        '''Signals a server thread to stop its work.

        Args:
            server_thread (:obj:`threading.Thread`): The thread to stop.
        '''
        if server_thread not in self.threads:
            return

        self.threads[server_thread]['stop'] = True
        self.threads[server_thread]['complete'] = True

    def remove_operation(self, server_thread):
        '''Removes operation from server thread structure.

        Args:
            server_thread (:obj:`threading.Thread`): The thread to remove.
        '''
        if server_thread in self.threads:
            del self.threads[server_thread]

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
        except FirstServerError as e:
            data = None

        return data and ('status' in data) and ('connected' == data['status'])

    #   Signature URLS
    def add(self, metadata, data_callback=None, complete_callback=None, architecture=None):
        '''Adds function metadata to FIRSTCore.

        This is a long operation, thus it has the option of providing a
        ``data_callback`` and ``complete_callback`` arguments. Those
        arguments are functions that will be called with the newly returned
        data and when the whole operation is complete, respectively. Both
        functions should follow the below their respective prototypes;
        ``data_callback_prototype`` and ``complete_callback_prototype``.

        Args:
            metadata (:obj:`list` of :obj:`dict`: The metadata to be added to FIRSTCore.
                metadata (dict): Dictionary of function metadata (type to be flled in later
                    {
                        address
                        signature
                        name
                        prototype
                        comment
                        apis
                        id
                    }
            data_callback (:obj:`data_callback_prototype`, optional):
                A function to call when data is receieved from the server.
            complete_callback (:obj:`complete_callback_prototype`, optional):
                A function to call when the whole long operation completes.
            architecture (:obj: 'str') string that's either ['intel32', 'intel64', 'arm32', 'mips']

        Returns:
            threading.Thread. The thread created for the operation.
        '''
        if self.multithreaded:
            args = (metadata, data_callback, complete_callback)
            thread = threading.Thread(target=self.__thread_add, args=args)
            thread.daemon = True
            thread.start()
            return thread
        else:
            self.__thread_add(metadata, data_callback, complete_callback, architecture)

    def __thread_add(self, metadata, data_callback=None, complete_callback=None, architecture=None):
        '''thread'''

        thread = threading.current_thread()
        self.threads[thread] = {'results': [], 'complete': False,
                                'stop': False}

        if not isinstance(metadata, list):
            metadata = [metadata]

        if isinstance(architecture, str):
            if architecture not in ['intel32', 'intel64', 'arm32', 'mips']:
                raise FirstServerError('Invalid architecture')
        else:
            raise FirstServerError('Invalid type')

        for i in xrange(0, len(metadata), self.MAX_CHUNK):
            params = self._min_info()
            data = {}
            for m in metadata[i:i + self.MAX_CHUNK]:
                data[m['address']] = {'architecture': architecture,
                                        'opcodes': b64encode(m['signature']),
                                        'name': m['name'],
                                       'prototype': m['prototype'],
                                       'comment': m['comment'],
                                       'apis': m['apis'],
                                       'id': m['id']}

            params['functions'] = json.dumps(data)
            try:
                response = self._sendp('add', params)
            except FirstServerError as e:
                self.threads[thread]['complete'] = True
                if complete_callback:
                    complete_callback(thread, self.threads[thread])
                return

            if response:
                self.threads[thread]['results'].append(response)
                if data_callback:
                    data_callback(thread, response)

            if self.threads[thread]['stop']:
                break

        self.threads[thread]['complete'] = True
        if complete_callback:
            complete_callback(thread, self.threads[thread])

    def history(self, metadata):
        '''Gets annotation history from FIRSTCore.

        This is a short operation and is a blocking call.

        Args:
            metadata (:obj:`dict`: The metadata to be added to FIRSTCore.
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

        if not re.match('^[\da-f]{25}$', FIRSTId):
            return None

        try:
            response = self._sendp('history', {'metadata': json.dumps([metadata])})
        except FirstServerError as e:
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
        except FirstServerError as e:
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
        except FirstServerError as e:
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
        except FirstServerError as e:
            return None

        return response

    def created(self, data_callback=None, complete_callback=None):
        '''Retrieves FIRSTCore annotations the user has created.

        This is a long operation, thus it has the option of providing a
        ``data_callback`` and ``complete_callback`` arguments. Those
        arguments are functions that will be called with the newly returned
        data and when the whole operation is complete, respectively. Both
        functions should follow the below their respective prototypes;
        ``data_callback_prototype`` and ``complete_callback_prototype``.

        Args:
            data_callback (:obj:`data_callback_prototype`, optional):
                A function to call when data is receieved from the server.
            complete_callback (:obj:`complete_callback_prototype`, optional):
                A function to call when the whole long operation completes.

        Returns:
            threading.Thread. The thread created for the operation.
        '''
        if self.multithreaded:
            args = (data_callback, complete_callback)
            thread = threading.Thread(target=self.__thread_created, args=args)
            thread.daemon = True
            thread.start()
            return thread
        else:
            self.__thread_created(data_callback, complete_callback)

    def __thread_created(self, data_callback=None, complete_callback=None):
        '''Thread to get created data'''
        thread = threading.current_thread()
        self.threads[thread] = {'results': [], 'complete': False,
                                'stop': False}
        page = 1
        total_pages = 0
        first_time = True
        while (first_time
               or ((page <= total_pages) and (not self.threads[thread]['stop']))):
            if first_time:
                first_time = False

            try:
                response = self._sendg('created', {'page': page})
            except FirstServerError as e:
                self.threads[thread]['complete'] = True
                if complete_callback:
                    complete_callback(thread, self.threads[thread])

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
                data = [MetadataServer(x, x['id']) for x in metadata]
                self.threads[thread]['results'].append(data)
                if data_callback:
                    data_callback(thread, data)

            page += 1

        self.threads[thread]['complete'] = True
        if complete_callback:
            complete_callback(thread, self.threads[thread])

    def get(self, metadata_ids, data_callback=None, complete_callback=None):
        '''Retrieves FIRSTCore annotations the user has created.

        This is a long operation, thus it has the option of providing a
        ``data_callback`` and ``complete_callback`` arguments. Those
        arguments are functions that will be called with the newly returned
        data and when the whole operation is complete, respectively. Both
        functions should follow the below their respective prototypes;
        ``data_callback_prototype`` and ``complete_callback_prototype``.

        Args:
            metadata (:obj:`list` of :obj:`MetadataShim`): The metadata to
                be retrieved from FIRSTCore.
            data_callback (:obj:`data_callback_prototype`, optional):
                A function to call when data is receieved from the server.
            complete_callback (:obj:`complete_callback_prototype`, optional):
                A function to call when the whole long operation completes.

        Returns:
            threading.Thread. The thread created for the operation.
        '''
        if self.multithreaded:
            args = (metadata_ids, data_callback, complete_callback)
            thread = threading.Thread(target=self.__thread_get, args=args)
            thread.daemon = True
            thread.start()
            return thread
        else:
            self.__thread_get(metadata_ids, data_callback, complete_callback)

    def __thread_get(self, metadata, data_callback=None, complete_callback=None):
        '''Thread to get metadata'''
        thread = threading.current_thread()
        self.threads[thread] = {'results': [], 'complete': False,
                                'stop': False}

        if not isinstance(metadata, list):
            metadata = [metadata]

        if False in [isinstance(m, dict) for m in metadata]:
            self.threads[thread]['complete'] = True
            return

        for i in xrange(0, len(metadata), self.MAX_CHUNK):
            if self.threads[thread]['stop']:
                break

            data = [m['id'] for m in metadata[i:i + self.MAX_CHUNK]]

            try:
                response = self._sendp('get', {'metadata': json.dumps(data)})
            except FirstServerError as e:
                self.threads[thread]['complete'] = True
                if complete_callback:
                    complete_callback(thread, self.threads[thread])
                return

            if (not response or ('results' not in response)
                    or (dict != type(response['results']))
                    or (not len(response['results']))):
                continue

            results = {}
            for metadata_id, details in response['results'].iteritems():
                results[metadata_id] = MetadataServer(details)

            if 0 < len(results):
                self.threads[thread]['results'].append(results)
                if data_callback:
                    data_callback(thread, results)

        self.threads[thread]['complete'] = True
        if complete_callback:
            complete_callback(thread, self.threads[thread])

    def scan(self, metadata, architecture, data_callback=None, complete_callback=None):
        '''Queries FIRSTCore for matches.

        This is a long operation, thus it has the option of providing a
        ``data_callback`` and ``complete_callback`` arguments. Those
        arguments are functions that will be called with the newly returned
        data and when the whole operation is complete, respectively. Both
        functions should follow the below their respective prototypes;
        ``data_callback_prototype`` and ``complete_callback_prototype``.

        Args:
            metadata (:obj:`list` of :obj:`MetadataShim`): The metadata to
                be queried for matches in FIRSTCore.
            data_callback (:obj:`data_callback_prototype`, optional):
                A function to call when data is receieved from the server.
            complete_callback (:obj:`complete_callback_prototype`, optional):
                A function to call when the whole long operation completes.
            architecture (:obj: 'str', valid architecture string. Valid values are: intel32, intel64, arm32, mips

        Returns:
            threading.Thread. The thread created for the operation.
        '''
        if self.multithreaded:
            args = (metadata, data_callback, complete_callback)
            thread = threading.Thread(target=self.__thread_scan, args=args)
            thread.daemon = True
            thread.start()
            return thread
        else:
            self.__thread_scan(metadata, data_callback, complete_callback, architecture)

    def __thread_scan(self, metadata, data_callback=None, complete_callback=None, architecture=None):
        '''Thread to query FIRSTCore for metadata'''
        thread = threading.current_thread()
        self.threads[thread] = {'results': [], 'complete': False,
                                'stop': False}

        if not isinstance(metadata, list):
            metadata = [metadata]

        if False in [isinstance(m, dict) for m in metadata]:
            self.threads[thread]['complete'] = True
            return

        subkeys = {'engines', 'matches'}

        for i in xrange(0, len(metadata), self.MAX_CHUNK):
            if self.threads[thread]['stop']:
                break

            params = self._min_info()
            data = {}
            for m in metadata[i:i + self.MAX_CHUNK]:
                signature = m['signature']
                if not signature:
                    continue
                #   Changed the encoding part
                data[m['address']] = {'opcodes': b64encode(m['signature']),
                                   'apis': m['apis'],
                                   'architecture': architecture}

            params['functions'] = json.dumps(data)

            try:
                response = self._sendp('scan', params)
            except FirstServerError as e:
                print(e)
                self.threads[thread]['complete'] = True
                if complete_callback:
                    complete_callback(thread, self.threads[thread])
                return

            if (not response or ('results' not in response)
                    or (dict != type(response['results']))
                    or (not subkeys.issubset(response['results'].keys()))
                    or (0 == len(response['results']['matches']))):
                continue

            results = {}
            engine_info = response['results']['engines']
            matches = response['results']['matches']
            for address_str in matches:
                functions = []
                address = int(address_str)

                for match in matches[address_str]:
                    engines = {x: engine_info[x] for x in match['engines']}
                    data = MetadataServer(match, address, engines)
                    functions.append(data)

                if len(functions) > 0:
                    results[address] = functions

            if 0 < len(results):
                self.threads[thread]['results'].append(results)
                if data_callback:
                    data_callback(thread, results)

        self.threads[thread]['complete'] = True
        if complete_callback:
            complete_callback(thread, self.threads[thread])
