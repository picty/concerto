#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>


int main (int argc, char* argv[]) {
  char* dest;
  int i;

  if (argc < 3) {
    fprintf (stderr, "Usage: %s destdir srcdir [srcdir2 ...]\n", argv[0]);
    exit (1);
  }
  dest = argv[1];
  mkdir (dest, 0755);

  for (i = 2; i < argc; i++) {
    DIR* dir;
    struct dirent* entry;

    dir = opendir (argv[i]);
    while ((entry = readdir(dir)) != NULL) {
      char* certname;
      char* srcfile = NULL;
      char* srcfile_backup = NULL;
      char* dstdir1 = NULL;
      char* dstdir2 = NULL;
      char* dstfile = NULL;
      struct stat buf;

      if (entry->d_type != DT_REG) continue;

      certname = entry->d_name;
      if (strlen (certname) < 5) {
        fprintf (stderr, "%s is not a valid cert name.\n", certname);
        exit (1);
      }

      if ((asprintf (&srcfile, "%s/%s", argv[i], certname) == -1) ||
          (asprintf (&srcfile_backup, "%s/%s.bak", argv[i], certname) == -1) ||
          (asprintf (&dstdir1, "%s/%c%c", dest, certname[0], certname[1]) == -1) ||
          (asprintf (&dstdir2, "%s/%c%c/%c%c", dest, certname[0],
                     certname[1], certname[2], certname[3]) == -1) ||
          (asprintf (&dstfile, "%s/%c%c/%c%c/%s", dest, certname[0],
                     certname[1], certname[2], certname[3], certname) == -1)) {
        fprintf (stderr, "Error while allocating strings.\n");
        exit (1);
      }

      if (stat (dstfile, &buf) == 0) {
        if (rename (srcfile, srcfile_backup) != 0 ||
            link (dstfile, srcfile) != 0 ||
            unlink (srcfile_backup) != 0) {
          printf ("Error while handling removing %s and linking it to %s.\n", srcfile, dstfile);
          exit (1);
        }
      } else {
        mkdir (dstdir1, 0755);
        mkdir (dstdir2, 0755);
        if (link (srcfile, dstfile) != 0) {;
          printf ("Error while linking linking %s to %s.\n", dstfile, srcfile);
          exit (1);
        }
      }
    }
    closedir (dir);
  }

  return 0;
}
