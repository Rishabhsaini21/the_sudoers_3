#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"

static void
check(char *what, int got, int want)
{
  if(got == want)
    printf(1, "PASS  %s (%d)\n", what, got);
  else
    printf(1, "FAIL  %s: got %d, want %d\n", what, got, want);
}

int
main(void)
{
  int p[2], fd;
  char b[8];

  fd = open("tpinbox.txt", O_CREATE | O_WRONLY);
  write(fd, "evil\n", 5);
  close(fd);
  marktaint("tpinbox.txt");
  pipe(p);

  if(fork() == 0){ write(p[1], "a", 1); exit(); }       // clean writer
  wait();
  if(fork() == 0){
    read(p[0], b, 1);
    check("reader of clean-only pipe stays clean", istainted(), 0);
    exit();
  }
  wait();

  if(fork() == 0){                                      // tainted writer
    int f = open("tpinbox.txt", O_RDONLY);
    read(f, b, sizeof(b));
    write(p[1], "T", 1);
    exit();
  }
  wait();
  if(fork() == 0){ write(p[1], "c", 1); exit(); }       // clean writer again
  wait();

  if(fork() == 0){
    read(p[0], b, 1);                                   // gets the tainted byte
    check("reader of tainted byte is tainted", istainted(), 1);
    exit();
  }
  wait();
  if(fork() == 0){
    read(p[0], b, 1);                                   // gets the CLEAN byte
    printf(1, "INFO  byte came from the clean writer, reader tainted=%d "
              "(per-pipe false positive, expected 1)\n", istainted());
    exit();
  }
  wait();
  unlink("tpinbox.txt");
  exit();
}