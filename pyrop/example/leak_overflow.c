//Simple example buffer overflow and memory leak
//Evan P. Jensen

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>

typedef enum _game_choice{
	INVALID=0,
	LEAK,
	OVERFLOW,
	EXIT
} game_choice;

game_choice menu(){
	puts("make a choose:\n"
		 "\t1.) leak address\n"
		 "\t2.) do_overflow\n"
		 "\t3.) exit\n"
		);

	char buf[0x10];
	memset(buf,0,sizeof(buf));
	fgets(buf,sizeof(buf)-1,stdin);
	return strtoul(buf,0,0);
}

void do_leak(){

	char buf[0x20];
	memset(buf,0,sizeof(buf));
	puts("what address would you like to peek at?");
	fgets(buf,sizeof(buf)-1,stdin);
	size_t* addr=(size_t*)strtoul(buf,0,0x10);
	printf("%p: %#x\n",addr,*addr);
	return;
}

void fix_buffering(void){
	setvbuf(stdin,  NULL, _IOLBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);

}

int main(int argc,char** argv){
	fix_buffering();

	game_choice choice;
	char buf[0x100];
	while((choice=menu())>INVALID && choice <=EXIT) {
		switch (choice)
		{
			case LEAK:
				do_leak();
				break;
			
			case OVERFLOW:
				fgets(buf,sizeof(buf)*5,stdin);
				break;
			case EXIT:
			default:
				return 0;

		}

	}

	puts("invalid");
	return 1;


}
