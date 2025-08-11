import sys
sys.path.append('../src/cython')
from mercury import *

database = './data/resources-test.tgz'
libmerc   = Mercury(do_analysis=True, resources=database.encode())

def main():
    str_repr = 'tls/(0303)(00ffc02cc02bc024c023c00ac009c008c030c02fc028c027c014c013c012009d009c003d003c0035002f000a)((0000)(000a00080006001700180019)(000b00020100)(000d0012001004010201050106010403020305030603)(000500050100000000)(0012)(0017))'
    server_name = 'alive.github.com'
    dst_ip = '140.82.112.26'
    dst_port = 443

    cls_result1 = libmerc.perform_analysis(str_repr, server_name, dst_ip, int(dst_port))
    cls_result2 = libmerc.perform_analysis_with_weights(str_repr, server_name, dst_ip, int(dst_port), '', 0.13924, 0.15590, 0.00528, 0.56735, 0.96941, 1.0)
    cls_result3 = libmerc.perform_analysis(str_repr, server_name, dst_ip, int(dst_port))
    score1 = round(cls_result1['analysis']['score'], 6)
    score2 = round(cls_result2['analysis']['score'], 6)
    score3 = round(cls_result3['analysis']['score'], 6)
    print("score1:", score1)
    print("score2:", score2)
    print("score3:", score3)
 
    if score1 != score3:
        print('Failed: Weight updates are not correct with perform_analysis_with_weights()')
        sys.exit(1)
    if score1 != 0.991746:
        print('Failed: Feature weights from resource file is not read correctly')
        sys.exit(1)

    sys.exit(0)

if __name__ == "__main__":
    main()
