import unittest
import bess_msg_pb2 as bess_msg
import error_pb2 as error_msg
import proto_conv


class TestProtobufConvert(unittest.TestCase):
    def test_protobuf_to_dict(self):
        pb = bess_msg.CreatePortResponse()
        pb.error.err = 1
        pb.error.errmsg = 'bar'
        pb.error.details = ''
        pb.name = 'foo'

        true_result = {
            'error': {
                'err': 1,
                'errmsg': 'bar',
            },
            'name': 'foo'
        }
        result = proto_conv.protobuf_to_dict(pb)
        self.assertEqual(true_result, result)

    def test_dict_to_protobuf(self):
        pb = bess_msg.CreatePortResponse()
        pb.error.err = 1
        pb.error.errmsg = 'bar'
        pb.error.details = ''
        pb.name = 'foo'

        msg_dict = {
            'error': {
                'err': 1,
                'errmsg': 'bar',
            },
            'name': 'foo'
        }

        msg = proto_conv.dict_to_protobuf(msg_dict,
                                          bess_msg.CreatePortResponse)
        self.assertEqual(msg, pb)

        pb = bess_msg.CreateModuleRequest()
        pb.name = 'm1'
        pb.mclass = 'bpf'

        kv = {
            'name': 'm1',
            'mclass': 'bpf',
        }
        msg = proto_conv.dict_to_protobuf(kv, bess_msg.CreateModuleRequest)
        self.assertEqual(msg, pb)
