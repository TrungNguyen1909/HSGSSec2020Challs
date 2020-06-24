#include "emu.h"
#include <stdio.h>
#include <string.h>
double score_registers_from_file(register_state_t state, const char* path){
	FILE* fd = fopen(path, "r");
	char reg[8];
	int64_t reg_value = 0;
	memset(reg,0,sizeof(reg));
	long count = 0;
	long correct = 0;
	while(fscanf(fd,"%4s = %llx\n",reg,&reg_value)==2){
		for(int i=0;i<regs_nums;i++)
		if(strncasecmp(reg, reg_names[i], strlen(reg))==0){
			correct += (reg_value == state->regs[i]?1:0);
			count ++;
			break;
		}
		memset(reg,0,sizeof(reg));
		reg_value = 0;
	}
	fclose(fd);
	if(count==0) return 0;
	else return (double)correct/(double)count;
}
register_state_t parse_regs_from_file(const char* path){
	FILE* fd = fopen(path, "r");
	char reg[8];
	int64_t reg_value = 0;
	memset(reg,0,sizeof(reg));
	register_state_t result = (register_state_t)calloc(1, sizeof(struct register_state));
	while(fscanf(fd, "%4s = %llx\n",reg,&reg_value)==2){
		for(int i=0;i<regs_nums;i++)
		if(strncasecmp(reg, reg_names[i], strlen(reg))==0){
			result->regs[i] = reg_value;
			break;
		}
		memset(reg,0,sizeof(reg));
		reg_value = 0;
	}
	fclose(fd);
	return result;
}
int main(int argc, char *argv[]){
	register_state_t output = parse_regs_from_file(argv[3]);
	printf("%lf\n", score_registers_from_file(output, argv[2]));
}
