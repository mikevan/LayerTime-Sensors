#include <lts/RemoteId.h>
#include "check.h"
#include <iostream>
int main() {
    uint8_t data[28] = {0x0d, 42, 0x02, 0x12, 'T','E','S','T'};
    lts::RemoteIdBasicClaim out;
    CHECK_TRUE(lts::parseRemoteIdBasicServiceData(0xfffa,data,27,out));
    CHECK_TRUE(out.counter==42 && out.protocolVersion==2 && out.idType==1 && out.aircraftType==2);
    CHECK_TRUE(out.identifier[0]=='T' && out.identifier[19]==0);
    for(size_t n=0;n<27;n++) CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffa,data,n,out));
    CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffa,data,28,out));
    CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffb,data,27,out));
    CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffa,nullptr,27,out));
    for(uint8_t bad: {uint8_t(0x12),uint8_t(0xf2),uint8_t(0x03)}) {
        data[2]=bad; CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffa,data,27,out));
        CHECK_TRUE(out.identifier[0]=='T');
    }
    data[2]=2; data[0]=0; CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffa,data,27,out));
    data[0]=0x0d; data[3]=2; CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffa,data,27,out));
    data[3]=0x52; CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffa,data,27,out));
    data[3]=0x32; data[4]=0xff; CHECK_TRUE(lts::parseRemoteIdBasicServiceData(0xfffa,data,27,out));
    CHECK_TRUE(out.identifier[0]==0xff); // binary IDs preserved, not treated as C strings
    for(size_t n=4;n<24;n++)data[n]=0;
    CHECK_TRUE(!lts::parseRemoteIdBasicServiceData(0xfffa,data,27,out));
    CHECK_SUMMARY();
}
