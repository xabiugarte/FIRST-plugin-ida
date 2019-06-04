from FirstServer import FIRSTServer 
from FirstServer import MetadataServer
import os
from base64 import b64decode

def create_first_connection():
    config = {'auth': None, 
              'server': "first.talosintelligence.com",
              'proto': "https",
              'port': 443,
              'verify': True,
              'api_key': os.environ.get('FIRST_API_KEY', None) }

    return FIRSTServer(config, 
                       'fe6aaa2d4844f5ee6e7e69fde2d3639d', 
                       1862706092, 
                       h_sha1 = 'b2fc96681b49e5361fed431f518fb755210f02b2',
                       h_sha256='8ec9cd069d8c347859247019062dbcccc25ff7005118689eb163f1af970eb047')

def test_test_connection():
    '''
        Test connection
    '''
    server = create_first_connection()
    assert(server)
    assert(server.test_connection())

def test_checkin():
    '''
        Test checkin
    '''
    server = create_first_connection()
    assert(server)
    server.checkin("")
    assert(server.checkedin)

def test_scan():
    '''
        Test scan for function
    '''
    global my_results

    server = create_first_connection()
    assert(server)


    def my_data_callback(thread, results):
        global my_results
        my_results = results

    def my_complete_callback(thread, thread_structure):
        pass

    my_results = None
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'apis': [],
                'address': 0xDEADC0DE }

    server.scan(metadata, "intel32", data_callback = my_data_callback, complete_callback = my_complete_callback)

    assert(my_results)
    assert(len(my_results) == 1)
    assert(0xDEADC0DE in my_results)
    assert(len(my_results[0xDEADC0DE]) > 0)
    assert(isinstance(my_results[0xDEADC0DE][0], MetadataServer))

def test_add():
    '''
        Test add function
    '''
    global my_results

    server = create_first_connection()
    assert(server)


    def my_data_callback(thread, results):
        global my_results
        my_results = results

    def my_complete_callback(thread, thread_structure):
        pass

    my_results = None
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'apis': [],
                'address': 0xDEADC0DE }

    server.scan(metadata, "intel32", data_callback = my_data_callback, complete_callback = my_complete_callback)

    assert(my_results)
    assert(len(my_results) == 1)
    assert(0xDEADC0DE in my_results)
    assert(len(my_results[0xDEADC0DE]) > 0)
    assert(isinstance(my_results[0xDEADC0DE][0], MetadataServer))
   
