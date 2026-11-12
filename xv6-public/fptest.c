#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

struct prog { char *name; char *argv[4]; };

static struct prog progs[] = {
  {"cat",   {"cat", "README", 0}},
  {"ls",    {"ls", ".", 0}},
  {"echo",  {"echo", "hi", 0}},
  {"grep",  {"grep", "xv6", "README", 0}},
  {"wc",    {"wc", "README", 0}},
  {"rm",    {"rm", "fpinbox.txt", 0}},
  {"mkdir", {"mkdir", "fpdir", 0}},
  {"ln",    {"ln", "README", "fplink", 0}},
};

static void
runas(char *path, char **argv)
{
  if(fork() == 0){
    char b[16];
    int f = open("fpinbox.txt", O_RDONLY);     // become tainted
    read(f, b, sizeof(b));
    close(f);
    exec(path, argv);
    printf(1, "  exec %s -> REFUSED or missing\n", path);
    exit();
  }
  wait();
}

int
main(void)
{
  int fd, i;
  char path[32];

  fd = open("fpinbox.txt", O_CREATE | O_WRONLY);
  write(fd, "evil\n", 5);
  close(fd);
  marktaint("fpinbox.txt");

  for(i = 0; i < sizeof(progs) / sizeof(progs[0]); i++){
    strcpy(path, "/safe/");
    strcpy(path + 6, progs[i].name);
    printf(1, "== tainted %s ==\n", path);
    runas(path, progs[i].argv);

    strcpy(path, "/");
    strcpy(path + 1, progs[i].name);
    printf(1, "== tainted %s ==\n", path);
    runas(path, progs[i].argv);
  }
  unlink("fpinbox.txt");
  unlink("fpdir");
  unlink("fplink");
  exit();
}