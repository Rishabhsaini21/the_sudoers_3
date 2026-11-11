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
  int fd;
  char b[64];

  // A: delete an untrusted file and recreate the name -> new file is clean
  fd = open("trf.txt", O_CREATE | O_WRONLY);
  write(fd, "evil\n", 5);
  close(fd);
  marktaint("trf.txt");
  check("clean parent unlinks untrusted file", unlink("trf.txt"), 0);
  fd = open("trf.txt", O_CREATE | O_WRONLY);
  write(fd, "fresh", 5);
  close(fd);
  if(fork() == 0){
    int f = open("trf.txt", O_RDONLY);
    int n = read(f, b, sizeof(b));
    check("recreated file readable", n, 5);
    check("reader of recreated file stays clean", istainted(), 0);
    exit();
  }
  wait();

  // B: data written by a tainted process lands in an untrusted file
  fd = open("trsrc.txt", O_CREATE | O_WRONLY);
  write(fd, "evil\n", 5);
  close(fd);
  marktaint("trsrc.txt");
  if(fork() == 0){
    int f = open("trsrc.txt", O_RDONLY);
    int o;
    read(f, b, sizeof(b));
    o = open("trout.txt", O_CREATE | O_WRONLY);
    write(o, "copy", 4);
    exit();
  }
  wait();
  if(fork() == 0){
    int f = open("trout.txt", O_RDONLY);
    read(f, b, sizeof(b));
    check("reader of tainted-written file is tainted", istainted(), 1);
    exit();
  }
  wait();

  unlink("trf.txt");
  unlink("trsrc.txt");
  unlink("trout.txt");
  exit();
}