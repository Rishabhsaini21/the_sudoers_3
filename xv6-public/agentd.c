// agentd.c -- guest-side tool runner for xv6-public (x86).
// Taint is per *process*. If every tool call were a fresh shell command, the
// process that read /inbox.txt (cat) would be different from the process that
// later tried to delete a file (rm), and the kernel could not connect them.
// So the agent's guest-side runtime is ONE long-lived process. It reads
// one-line commands from the console (QEMU serial), runs them in-process and
// prints the result. After it reads an untrusted file, the KERNEL taints it,
// and its later unlink() is refused -- no matter what the host-side agent or
// the LLM believes.
//
// PROTOCOL (one command per line, fixed verbs only):
//   LIST            list files in /
//   READ <path>     print file contents
//   DEL  <path>     unlink(path)          (dangerous; kernel may refuse)
//   MARK <path>     marktaint(path)       (setup only; not exposed as a tool)
//   QUIT            exit agentd (back to the xv6 shell, new process = clean)
// Every command ends with a line:  @@END rc=<n> tainted=<0|1>

#include "types.h"
#include "stat.h"
#include "user.h"
#include "fcntl.h"
#include "fs.h"

#define MAXLINE 100

static int
readline(char *buf, int max)
{
  int i = 0;
  char c;

  while(i < max - 1){
    if(read(0, &c, 1) < 1){
      if(i == 0)
        return -1;
      break;
    }
    if(c == '\n')
      break;
    buf[i++] = c;
  }
  buf[i] = 0;
  return i;
}

static int
do_list(void)
{
  int fd;
  struct dirent de;

  if((fd = open(".", O_RDONLY)) < 0)
    return -1;
  while(read(fd, &de, sizeof(de)) == sizeof(de)){
    if(de.inum == 0)
      continue;
    if(de.name[0] == '.')      // skip . and ..
      continue;
    printf(1, "%s\n", de.name);
  }
  close(fd);
  return 0;
}

static int
do_read(char *path)
{
  int fd, n;
  char buf[128];
  char last = '\n';

  if((fd = open(path, O_RDONLY)) < 0){
    printf(1, "cannot open %s\n", path);
    return -1;
  }
  while((n = read(fd, buf, sizeof(buf))) > 0){
    write(1, buf, n);
    last = buf[n - 1];
  }
  close(fd);
  if(last != '\n')
    printf(1, "\n");
  return n < 0 ? -1 : 0;
}

static int
do_del(char *path)
{
  int rc = unlink(path);
  printf(1, "unlink(%s) = %d\n", path, rc);
  return rc;
}

static int
do_mark(char *path)
{
  int rc = marktaint(path);
  printf(1, "marktaint(%s) = %d\n", path, rc);
  return rc;
}

int
main(void)
{
  char line[MAXLINE];
  char *arg;
  int rc;

  printf(1, "@@READY\n");
  for(;;){
    if(readline(line, sizeof(line)) < 0)
      break;

    // split "VERB arg"
    arg = line;
    while(*arg && *arg != ' ')
      arg++;
    if(*arg){
      *arg++ = 0;
      while(*arg == ' ')
        arg++;
    }

    if(strcmp(line, "QUIT") == 0)
      break;
    else if(strcmp(line, "LIST") == 0)
      rc = do_list();
    else if(strcmp(line, "READ") == 0 && *arg)
      rc = do_read(arg);
    else if(strcmp(line, "DEL") == 0 && *arg)
      rc = do_del(arg);
    else if(strcmp(line, "MARK") == 0 && *arg)
      rc = do_mark(arg);
    else {
      printf(1, "bad command\n");
      rc = -1;
    }
    printf(1, "\n@@END rc=%d tainted=%d\n", rc, istainted());
  }
  exit();
}
