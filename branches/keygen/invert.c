#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
	char *infile, *outfile;
	FILE *fpin, *fpout;
	int c;
	long file_length;

	if(argc != 2) {
		printf ("usage: ./invert file_to_invert\n");
		return -1;
	}

	infile = argv[1];
	outfile = (char *)malloc((strlen(infile) + 9)*sizeof(char *));
	sprintf(outfile, "%s-inverted", infile);
	printf("invert file %s\n", infile);

	fpin = fopen(infile, "r");
	fpout = fopen(outfile, "w");
	fseek(fpin, -1, SEEK_END);
	file_length = ftell(fpin);

	while(file_length >= 0) {
		c = fgetc(fpin);
		fputc(c, fpout);
		fseek(fpin, -2, SEEK_CUR);
		file_length--;
	}

	free(outfile);
	fclose(fpin);
	fclose(fpout);
	return 0;
}
