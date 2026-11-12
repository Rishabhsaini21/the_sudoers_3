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
  int p[2], fd, d, f;
  char b[64];

  fd = open("tdinbox.txt", O_CREATE | O_WRONLY);
  write(fd, "evil\n", 5);
  close(fd);
  marktaint("tdinbox.txt");
  pipe(p);

  if(fork() == 0){                   // tainted writer, writes through a DUP
    f = open("tdinbox.txt", O_RDONLY);
    read(f, b, sizeof(b));
    check("writer tainted", istainted(), 1);
    d = dup(p[1]);
    close(p[1]);
    write(d, "x", 1);
    exit();
  }
  wait();
  close(p[1]);

  if(fork() == 0){                   // clean reader
    check("reader clean before", istainted(), 0);
    read(p[0], b, sizeof(b));
    check("reader tainted via dup'd write end", istainted(), 1);
    exit();
  }
  wait();

  if(fork() == 0){                   // dup of a file descriptor
    f = open("tdinbox.txt", O_RDONLY);
    read(f, b, sizeof(b));
    fd = open("README", O_WRONLY);
    d = dup(fd);
    close(fd);
    check("write via dup'd fd to clean file refused", write(d, "x", 1), -1);
    exit();
  }
  wait();
  unlink("tdinbox.txt");
  exit();
}