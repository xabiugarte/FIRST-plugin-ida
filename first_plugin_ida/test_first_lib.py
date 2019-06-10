from first_lib import FIRSTServer 
from first_lib import FunctionMetadata
import os
from base64 import b64decode
import threading

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

    # First add the function we are going to scan
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'name': "test_function",
                'prototype': "int test_fuction()",
                'comment': "This is a comment for test_function",
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE
                }

    my_results = server.add(metadata, "intel32")

    assert(my_results)

    if 0xDEADC0DE in my_results:
        metadata_id = my_results[0xDEADC0DE]


    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'apis': [],
                'address': 0xDEADC0DE }

    my_results = server.scan(metadata, "intel32")

    assert(my_results)
    assert(len(my_results) == 1)
    assert(0xDEADC0DE in my_results)
    assert(len(my_results[0xDEADC0DE]) > 0)
    assert(isinstance(my_results[0xDEADC0DE][0], FunctionMetadata))

def test_scan_async():
    '''
        Test scan for function
    '''
    global is_complete
    global total_result_length
    global partial_result_length
    global my_results

    is_complete = False
    total_result_length = 0
    partial_result_length = 0

    server = create_first_connection()
    assert(server)

    # First add the function we are going to scan
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'name': "test_function",
                'prototype': "int test_fuction()",
                'comment': "This is a comment for test_function",
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE }

    add_results = server.add(metadata, "intel32")

    assert(add_results)

    if 0xDEADC0DE in add_results:
        metadata_id = add_results[0xDEADC0DE]

    def my_data_callback(sub_results):
        global total_result_length
        global partial_result_length
        for address in sub_results:
            partial_result_length += len(sub_results[address])

    def my_complete_callback(results):
        global my_results
        global is_complete
        global total_result_length
        global partial_result_length

        is_complete = True
        my_results = results
        for address in results:
            total_result_length += len(results[address])


    is_complete = False
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'apis': [],
                'address': 0xDEADC0DE}

    my_results = None
    args = (metadata, "intel32", my_data_callback, my_complete_callback)
    thread = threading.Thread(target=server.scan, args=args)
    thread.daemon = True
    thread.start()

    # Wait until operation is complete
    import time
    while not is_complete:
        time.sleep(0.1)

    assert(my_results)
    assert(total_result_length == partial_result_length)
    assert(total_result_length > 0)
    assert(0xDEADC0DE in my_results)
    assert(len(my_results[0xDEADC0DE]) > 0)
    assert(isinstance(my_results[0xDEADC0DE][0], FunctionMetadata))


    # Now do it again, but stop the execution of the function
    is_complete = False
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'apis': [],
                'address': 0xDEADC0DE}

    def my_should_stop():
        return True

    total_result_length = 0
    partial_result_length = 0
    my_results = None
    args = (metadata, "intel32", my_data_callback, my_complete_callback, my_should_stop)
    thread = threading.Thread(target=server.scan, args=args)
    thread.daemon = True
    thread.start()

    # Wait until operation is complete
    import time
    while not is_complete:
        time.sleep(0.1)

    assert(my_results is not None)
    assert(total_result_length == partial_result_length)
    assert(total_result_length == 0)

def test_add_scan_modify_history_delete():
    '''
        Test add, scan, modify, delete, function.
        
        Adds a function, scans it, modifies it, scans it again, deletes it.
    '''
    global my_results

    server = create_first_connection()
    assert(server)

    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'name': "test_function",
                'prototype': "int test_fuction()",
                'comment': "This is a comment for test_function",
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE
                }

    my_results = server.add(metadata, "intel32")

    assert(my_results)

    if 0xDEADC0DE in my_results:
        metadata_id = my_results[0xDEADC0DE]

    # Scan for that function
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE }

    my_results = server.scan(metadata, "intel32")

    assert(my_results)
    assert(len(my_results) == 1)
    assert(0xDEADC0DE in my_results)
    assert(len(my_results[0xDEADC0DE]) > 0)
    found = False
    for m in my_results[0xDEADC0DE]:
        assert(isinstance(m, FunctionMetadata))
        if m.prototype == "int test_fuction()":
            found = True
    assert(found)

    # Now modify it, and make sure we find the modified version
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'name': "test_function2",
                'prototype': "int test_fuction2()",
                'comment': "This is a comment for test_function, modified",
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE,
                'id': metadata_id
                }

    my_results = server.add(metadata, "intel32")

    assert(my_results)
    assert(0xDEADC0DE in my_results)

    # Scan for that function again
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE }

    my_results = server.scan(metadata, "intel32")

    assert(my_results)
    assert(len(my_results) == 1)
    assert(0xDEADC0DE in my_results)
    assert(len(my_results[0xDEADC0DE]) > 0)
    found = False
    for m in my_results[0xDEADC0DE]:
        assert(isinstance(m, FunctionMetadata))
        if m.prototype == "int test_fuction2()":
            found = True
    assert(found)

    # Check history
    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'name': "test_function2",
                'prototype': "int test_fuction2()",
                'comment': "This is a comment for test_function, modified",
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE,
                'id': metadata_id
                }

    results = server.history(metadata)
    assert(results)

    # delete the function
    response = server.delete(metadata_id)
    assert(response)
    assert('failed' in response and not response['failed'])
    assert('deleted' in response and response['deleted'])

def test_add_apply_unapply():
    '''
        Test add, apply, unapply 
    '''
    server = create_first_connection()
    assert(server)

    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'name': "test_function",
                'prototype': "int test_fuction()",
                'comment': "This is a comment for test_function",
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE
                }

    my_results = server.add(metadata, "intel32")

    assert(my_results)

    if 0xDEADC0DE in my_results:
        metadata_id = my_results[0xDEADC0DE]

    response = server.applied(metadata_id)
    assert('failed' in response and not response['failed'])
    assert('results' in response and response['results'])
    response = server.unapplied(metadata_id)
    assert('failed' in response and not response['failed'])
    assert('results' in response and response['results'])

def test_add_created_get():
    server = create_first_connection()
    assert(server)

    metadata = {'signature': b64decode("VYvsi0UIZosIg8ACZoXJdfUrRQjR+Ehdww=="),
                'name': "test_function",
                'prototype': "int test_fuction()",
                'comment': "This is a comment for test_function",
                'apis': ["CreateProcessA"],
                'address': 0xDEADC0DE
                }

    my_results = server.add(metadata, "intel32")

    assert(my_results)

    if 0xDEADC0DE in my_results:
        metadata_id = my_results[0xDEADC0DE]

    results = server.created()
    assert(results)
    assert(len(results) > 0)
    found = False
    for m in results:
        assert(isinstance(m, FunctionMetadata))
        if m.prototype == "int test_fuction()":
            found = True
    assert(found)

    results = server.get(metadata_id)

    assert(results)
    assert(len(results) == 1)
    assert(metadata_id in results)
    m = results[metadata_id]
    assert(isinstance(m, FunctionMetadata))
    assert(m.prototype == "int test_fuction()")
