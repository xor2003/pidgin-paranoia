#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	FILE *fp;
	int c, i, count, race, one, zero;
	char byte;
	double zero_rate, one_rate;
	int halfbyte[16];
	int changes[4], last, check;
	short lastbit;

	for(i = 0; i < 16; i++) halfbyte[i] = 0;
	zero = 0;
	one = 0;
	lastbit = -1;
	race = 0;
	count = 0;


	if(argc != 2) {
		printf("useage: ./check_entropy file\n");
		return -1;
	}

	if((fp = fopen(argv[1], "r")) == NULL) {
		printf("file doesn't exists or is not readable\n");
		return -1;
	}

	zero = 0;
	one = 0;
	last = 0;
	check = 0;
	for(i = 0; i < 4; i++) changes[i] = 0;
	for(i = 0; i < 16; i++) halfbyte[i] = 0;

	while((c = fgetc(fp)) != EOF) {
		byte = (char)c;
		for(i = 0; i < 8; i++) {
			if(((c >> i) & 0x01) == 1) {
				one++;
				if(check) {
					if(last == 0) changes[1]++;
					if(last == 1) changes[3]++;
					check = 0;
				} else check = 1;
				last = 1;
			} else {
				zero++;
				if(check) {
					if(last == 0) changes[0]++;
					if(last == 1) changes[2]++;
					check = 0;
				} else check = 1;
				last = 0;
			}
			if(((c >> i) & 0x01) == lastbit) {
				count++;
			} else {
				if(race < count) race = count;
				count = 0;
				lastbit = ((c >> i) & 0x01);
			}
		}
		halfbyte[(int)(byte & 0x0F)]++;
		halfbyte[(int)((byte & 0xF0) >> 4)]++;
	}

	zero_rate =(double)zero/(zero + one);
	one_rate = (double)one/(zero + one);

	printf("rate of 0: %f\nrate of 1: %f\n", zero_rate, one_rate);
	printf("changes 00: %i\n", changes[0]);
	printf("changes 01: %i\n", changes[1]);
	printf("changes 10: %i\n", changes[2]);
	printf("changes 11: %i\n", changes[3]);
	for(i = 0; i < 16; i++) printf("Halfbyte rate for %i: %f\n", i, ((double)halfbyte[i]*4/(zero + one)));
	printf("longest race: %i\n", race);
	fclose(fp);
	return 0;
}
