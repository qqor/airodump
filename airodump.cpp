#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <vector>

#include <pcap.h>

using namespace std;
vector<struct binfo> info_vec;

#pragma pack(push, 1)
struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
} __attribute__((__packed__));

struct bframe {
	u_int8_t type;
	u_int8_t flags;
	u_int16_t duration;
	u_int8_t dmac[6];
	u_int8_t smac[6];
	u_int8_t bssid[6];
	u_int16_t ord;
	u_int8_t fparam[12];
	u_int8_t tagnum;
	u_int8_t len;
};

struct binfo {
	u_int8_t bssid[6];
	int beacon = 0;
	char *name;
};
#pragma pack(pop)

int find_bssid(u_int8_t* bssid) {
	for(int i = 0 ; i < info_vec.size() ; i++) {
		if(!memcmp(info_vec[i].bssid, bssid, 6)) {
			info_vec[i].beacon++; // ++
			return 0;
		}
	}
	return -1;
}

void usage() {
	printf("syntax : airodump <interface>\n");
	printf("sample : airodump mon0\n");
}

int main(int argc, char* argv[]) {
    
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* hdl = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    
    if (hdl == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }
    
    int cnt = 0;
    while(1) {
    	struct pcap_pkthdr* hdr;
    	const u_char* pkt;
    	int res = pcap_next_ex(hdl, &hdr, &pkt);

    	if (res == 0)
            continue;
        
        if (res == -1 || res == -2)  {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(hdl));
            break;
        }

        struct bframe* bf;
        bf = (struct bframe*)malloc(sizeof(struct bframe));

        u_int16_t hlen = *(pkt + 2);
        memcpy(bf, pkt + hlen, sizeof(struct bframe));

        if(bf->type == 0x80) {
            struct binfo tmp_info;
            
            for(int i = 0 ; i < 6 ; i++)
                tmp_info.bssid[i] = bf->bssid[i];

            tmp_info.name = (char*)malloc((int)bf->len);
            memcpy(tmp_info.name, pkt + hlen + sizeof(struct bframe), bf->len);
            
            int res = find_bssid(tmp_info.bssid);
            if(res == -1) {
                tmp_info.beacon++;
                info_vec.push_back(tmp_info);
                return;
            }

            free(tmp_info.name);
        }

        system("clear");
        
        printf("BSSID\t\t\tBeacon\tName\n");
        for(int i = 0 ; i < info_vec.size() ; i++) {
            printf("%02X:%02X:%02X:%02X:%02X:%02X\t", info_vec[i].bssid[0],info_vec[i].bssid[1],info_vec[i].bssid[2],info_vec[i].bssid[3],info_vec[i].bssid[4],info_vec[i].bssid[5]);		
            printf("%d\t%s\n", info_vec[i].beacon, info_vec[i].name);
        }

    }
}