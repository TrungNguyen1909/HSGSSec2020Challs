#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <keystone/keystone.h>
#include <unicorn/unicorn.h>
#include "emu.h"
#include "source.h"

#define ADDRESS 0x1000000

static void hook_syscall(uc_engine *uc, void *user_data) {
	uint64_t rax;
	uc_reg_read(uc, UC_X86_REG_RAX, &rax);

}
register_state_t start_emulation(unsigned char* asmbuf,size_t size, register_state_t init_regs){
	uc_engine *uc;
	uc_err err;
	uc_hook trace1;	
	fprintf(stderr, "Starting emulation...\n");
	
	err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
	if(err!=UC_ERR_OK){
		fprintf(stderr, "Failed uc_open(): %d, %s\n", err,uc_strerror(err));
		exit(3);
	}
	uc_hook_add(uc, &trace1, UC_HOOK_INSN, hook_syscall, NULL, 1, 0, UC_X86_INS_SYSCALL);
	//Alignment
	size_t executable_size = size;
	executable_size &=((-1ULL)<<12);
	executable_size += (1LL<<12);
	//Map binary
	uc_mem_map(uc, ADDRESS, executable_size, UC_PROT_ALL);
	uc_mem_write(uc, ADDRESS, asmbuf, size);
	
	//Map stack
	int64_t stack_top = ((int64_t)(&uc)&((-1ULL<<12)));
	uc_mem_map(uc, stack_top, 0x20000, UC_PROT_ALL);
	int64_t rsp = stack_top + 0x20000 - (1ULL<<12);
	
	//Initailize registers
	void* ptr[regs_nums];
	for(int i=0;i<regs_nums;i++){
		ptr[i] = &init_regs->regs[i];
	}
	uc_reg_write_batch(uc, regs, ptr, regs_nums);
	if(!init_regs->nostack){
		uc_reg_write(uc, UC_X86_REG_RSP, &rsp);
		uc_reg_write(uc, UC_X86_REG_RBP, &rsp);
	}
	err = uc_emu_start(uc, ADDRESS, ADDRESS + size - 1, 500000, 0);//0.5 seconds timeout
	if (err!=UC_ERR_OK) {
		fprintf(stderr,"Failed on uc_emu_start() with error returned %u: %s\n",	err, uc_strerror(err));
		exit(4);
	}
	register_state_t result = calloc(1, sizeof(struct register_state));
	for(int i=0;i<regs_nums;i++){
			ptr[i] = &result->regs[i];
		}
	uc_reg_read_batch(uc, regs, ptr, regs_nums);
	// now print out some registers
	fprintf(stderr, ">>> Emulation done.\n");
	for(int i=0;i<regs_nums;i++)
	printf("%s = 0x%lx\n", reg_names[i], result->regs[i]);
	uc_close(uc);
	return result;
}
register_state_t parse_init_regs(){
	char reg[8];
	int64_t reg_value = 0;
	memset(reg,0,sizeof(reg));
	register_state_t result = calloc(1, sizeof(struct register_state));
	while(scanf("%4s = %lx\n",reg,&reg_value)==2){
		for(int i=0;i<sizeof(reg_names)/sizeof(long);i++)
		if(strncasecmp(reg, reg_names[i], strlen(reg))==0){
			result->regs[i] = reg_value;
			break;
		}
		memset(reg,0,sizeof(reg));
		reg_value = 0;
	}
	return result;
}
double score_registers_from_file(register_state_t state, const char* path){
	FILE* fd = fopen(path, "r");
	char reg[8];
	int64_t reg_value = 0;
	memset(reg,0,sizeof(reg));
	long count = 0;
	long correct = 0;
	register_state_t result = calloc(1, sizeof(struct register_state));
	while(fscanf(fd,"%4s = %lx\n",reg,&reg_value)==2){
		for(int i=0;i<sizeof(reg_names)/sizeof(long);i++)
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
int main(int argc, char *argv[]) {
	ks_engine *ks;
	ks_err err;
	size_t count;
	unsigned char *asmbuf;
	size_t size;
	
	char* inbuf = calloc(1, code_cc_len+1);
	assert(inbuf!=0);
	memcpy(inbuf, code_cc, code_cc_len);
	fprintf(stderr, "Compiling...");
	err = ks_open(KS_ARCH_X86, KS_MODE_64, &ks);
	if(err!=KS_ERR_OK){
		fprintf(stderr, "Failed to open keystone engine");
		exit(1);
	}
	if(ks_asm(ks, inbuf, ADDRESS, &asmbuf, &size, &count)!=KS_ERR_OK){
		fprintf(stderr, "ERROR: ks_asm() failed & count = %lu, error = %u\n", count, ks_errno(ks));
		exit(2);
	}
	fprintf(stderr, "Compiled: %lu bytes, statements: %lu\n", size, count);
	register_state_t init_regs = parse_init_regs();
	register_state_t result_regs = start_emulation(asmbuf,size,init_regs);
	free(init_regs);
	free(result_regs);
	ks_free(asmbuf);
	ks_close(ks);
}
