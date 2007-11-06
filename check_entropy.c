#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	FILE *fp;
	int c, i;
	unsigned char byte;
	double zero_rate, one_rate, one, zero;

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

	while((c = fgetc(fp)) != EOF) {
		byte = (char)c;
		for(i = 0; i < 8; i++) {
			if(((c >> i) & 0x01) == 1) one++;
			else zero++;
		}
	}

	zero_rate = zero/(zero + one);
	one_rate = one/(zero + one);

	printf("Number of 0: %f\nNumber of 1: %f\n", zero_rate, one_rate);
	fclose(fp);
	return 0;
}
