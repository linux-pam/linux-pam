/* mkhomedir_helper - helper for pam_mkhomedir module

   Released under the GNU LGPL version 2 or later

   Copyright (c) Red Hat, Inc., 2009
   Originally written by Jason Gunthorpe <jgg@debian.org> Feb 1999
   Structure taken from pam_lastlogin by Andrew Morgan
     <morgan@parc.power.net> 1996
 */

#include "config.h"

#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pwd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <syslog.h>

#include <security/pam_ext.h>
#include <security/pam_modutil.h>

static unsigned long u_mask = 0022;
static char skeldir[BUFSIZ] = "/etc/skel";

/* Do the actual work of creating a home dir */
static int
create_homedir(const struct passwd *pwd,
	       const char *source, const char *dest)
{
   char remark[BUFSIZ];
   DIR *d;
   struct dirent *dent;
   int retval = PAM_SESSION_ERR;

   /* Create the new directory */
   if (mkdir(dest, 0700) && errno != EEXIST)
   {
      pam_syslog(NULL, LOG_ERR, "unable to create directory %s: %m", dest);
      return PAM_PERM_DENIED;
   }

   /* See if we need to copy the skel dir over. */
   if ((source == NULL) || (strlen(source) == 0))
   {
      retval = PAM_SUCCESS;
      goto go_out;
   }

   /* Scan the directory */
   d = opendir(source);
   if (d == NULL)
   {
      pam_syslog(NULL, LOG_DEBUG, "unable to read directory %s: %m", source);
      retval = PAM_PERM_DENIED;
      goto go_out;
   }

   for (dent = readdir(d); dent != NULL; dent = readdir(d))
   {
      int srcfd;
      int destfd;
      int res;
      struct stat st;
#ifndef PATH_MAX
      char *newsource = NULL, *newdest = NULL;
      /* track length of buffers */
      int nslen = 0, ndlen = 0;
      int slen = strlen(source), dlen = strlen(dest);
#else
      char newsource[PATH_MAX], newdest[PATH_MAX];
#endif

      /* Skip some files.. */
      if (strcmp(dent->d_name,".") == 0 ||
	  strcmp(dent->d_name,"..") == 0)
	 continue;

      /* Determine what kind of file it is. */
#ifndef PATH_MAX
      nslen = slen + strlen(dent->d_name) + 2;

      if (nslen <= 0)
	{
	  retval = PAM_BUF_ERR;
	  goto go_out;
	}

      if ((newsource = malloc(nslen)) == NULL)
	{
	  retval = PAM_BUF_ERR;
	  goto go_out;
	}

      sprintf(newsource, "%s/%s", source, dent->d_name);
#else
      snprintf(newsource, sizeof(newsource), "%s/%s", source, dent->d_name);
#endif

      if (lstat(newsource, &st) != 0)
#ifndef PATH_MAX
      {
	      free(newsource);
	      newsource = NULL;
         continue;
      }
#else
      continue;
#endif


      /* We'll need the new file's name. */
#ifndef PATH_MAX
      ndlen = dlen + strlen(dent->d_name)+2;

      if (ndlen <= 0)
	{
	  retval = PAM_BUF_ERR;
	  goto go_out;
	}

      if ((newdest = malloc(ndlen)) == NULL)
	{
	  free (newsource);
	  retval = PAM_BUF_ERR;
	  goto go_out;
	}

      sprintf (newdest, "%s/%s", dest, dent->d_name);
#else
      snprintf (newdest, sizeof (newdest), "%s/%s", dest, dent->d_name);
#endif

      /* If it's a directory, recurse. */
      if (S_ISDIR(st.st_mode))
      {
         retval = create_homedir(pwd, newsource, newdest);

#ifndef PATH_MAX
	 free(newsource); newsource = NULL;
	 free(newdest); newdest = NULL;
#endif

         if (retval != PAM_SUCCESS)
	   {
	     closedir(d);
	     goto go_out;
	   }
         continue;
      }

      /* If it's a symlink, create a new link. */
      if (S_ISLNK(st.st_mode))
      {
	 int pointedlen = 0;
#ifndef PATH_MAX
	 char *pointed = NULL;
           {
		   int size = 100;

		   while (1) {
			   pointed = malloc(size);
			   if (pointed == NULL) {
				   free(newsource);
				   free(newdest);
				   return PAM_BUF_ERR;
			   }
			   pointedlen = readlink(newsource, pointed, size);
			   if (pointedlen < 0) break;
			   if (pointedlen < size) break;
			   free(pointed);
			   size *= 2;
		   }
	   }
	   if (pointedlen < 0)
		   free(pointed);
	   else
		   pointed[pointedlen] = 0;
#else
         char pointed[PATH_MAX];
         memset(pointed, 0, sizeof(pointed));

         pointedlen = readlink(newsource, pointed, sizeof(pointed) - 1);
#endif

	 if (pointedlen >= 0) {
            if(symlink(pointed, newdest) == 0)
            {
               if (lchown(newdest, pwd->pw_uid, pwd->pw_gid) != 0)
               {
                   pam_syslog(NULL, LOG_DEBUG,
			      "unable to change perms on link %s: %m", newdest);
                   closedir(d);
#ifndef PATH_MAX
		   free(pointed);
		   free(newsource);
		   free(newdest);
#endif
                   return PAM_PERM_DENIED;
               }
            }
#ifndef PATH_MAX
	    free(pointed);
#endif
         }
#ifndef PATH_MAX
	 free(newsource); newsource = NULL;
	 free(newdest); newdest = NULL;
#endif
         continue;
      }

      /* If it's not a regular file, it's probably not a good idea to create
       * the new device node, FIFO, or whatever it is. */
      if (!S_ISREG(st.st_mode))
      {
#ifndef PATH_MAX
	 free(newsource); newsource = NULL;
	 free(newdest); newdest = NULL;
#endif
         continue;
      }

      /* Open the source file */
      if ((srcfd = open(newsource, O_RDONLY)) < 0 || fstat(srcfd, &st) != 0)
      {
         pam_syslog(NULL, LOG_DEBUG,
		    "unable to open or stat src file %s: %m", newsource);
         closedir(d);

#ifndef PATH_MAX
	 free(newsource); newsource = NULL;
	 free(newdest); newdest = NULL;
#endif

	 return PAM_PERM_DENIED;
      }

      /* Open the dest file */
      if ((destfd = open(newdest, O_WRONLY | O_TRUNC | O_CREAT, 0600)) < 0)
      {
         pam_syslog(NULL, LOG_DEBUG,
		    "unable to open dest file %s: %m", newdest);
	 close(srcfd);
	 closedir(d);

#ifndef PATH_MAX
	 free(newsource); newsource = NULL;
	 free(newdest); newdest = NULL;
#endif
	 return PAM_PERM_DENIED;
      }

      /* Set the proper ownership and permissions for the module. We make
         the file a+w and then mask it with the set mask. This preseves
	 execute bits */
      if (fchmod(destfd, (st.st_mode | 0222) & (~u_mask)) != 0 ||
	  fchown(destfd, pwd->pw_uid, pwd->pw_gid) != 0)
      {
         pam_syslog(NULL, LOG_DEBUG,
		    "unable to change perms on copy %s: %m", newdest);
         close(srcfd);
         close(destfd);
         closedir(d);

#ifndef PATH_MAX
	 free(newsource); newsource = NULL;
	 free(newdest); newdest = NULL;
#endif

	 return PAM_PERM_DENIED;
      }

      /* Copy the file */
      do
      {
	 res = pam_modutil_read(srcfd, remark, sizeof(remark));

	 if (res == 0)
	     continue;

	 if (res > 0) {
	     if (pam_modutil_write(destfd, remark, res) == res)
		continue;
	 }

	 /* If we get here, pam_modutil_read returned a -1 or
	    pam_modutil_write returned something unexpected. */
	 pam_syslog(NULL, LOG_DEBUG, "unable to perform IO: %m");
	 close(srcfd);
	 close(destfd);
	 closedir(d);

#ifndef PATH_MAX
	 free(newsource); newsource = NULL;
	 free(newdest); newdest = NULL;
#endif

	 return PAM_PERM_DENIED;
      }
      while (res != 0);
      close(srcfd);
      close(destfd);

#ifndef PATH_MAX
      free(newsource); newsource = NULL;
      free(newdest); newdest = NULL;
#endif

   }
   closedir(d);

   retval = PAM_SUCCESS;

 go_out:

   if (chmod(dest, 0777 & (~u_mask)) != 0 ||
       chown(dest, pwd->pw_uid, pwd->pw_gid) != 0)
   {
      pam_syslog(NULL, LOG_DEBUG,
		 "unable to change perms on directory %s: %m", dest);
      return PAM_PERM_DENIED;
   }

   return retval;
}

static int
make_parent_dirs(char *dir, int make)
{
  int rc = PAM_SUCCESS;
  char *cp = strrchr(dir, '/');
  struct stat st;

  if (!cp)
    return rc;

  if (cp != dir) {
    *cp = '\0';
    if (stat(dir, &st) && errno == ENOENT)
      rc = make_parent_dirs(dir, 1);
    *cp = '/';

    if (rc != PAM_SUCCESS)
      return rc;
  }

  if (make && mkdir(dir, 0755) && errno != EEXIST) {
    pam_syslog(NULL, LOG_ERR, "unable to create directory %s: %m", dir);
    return PAM_PERM_DENIED;
  }

  return rc;
}

int
main(int argc, char *argv[])
{
   struct passwd *pwd;
   struct stat st;

   if (argc < 2) {
	fprintf(stderr, "Usage: %s <username> [<umask> [<skeldir>]]\n", argv[0]);
	return PAM_SESSION_ERR;
   }

   pwd = getpwnam(argv[1]);
   if (pwd == NULL) {
	pam_syslog(NULL, LOG_ERR, "User unknown.");
	return PAM_CRED_INSUFFICIENT;
   }

   if (argc >= 3) {
	char *eptr;
	errno = 0;
	u_mask = strtoul(argv[2], &eptr, 0);
	if (errno != 0 || *eptr != '\0') {
		pam_syslog(NULL, LOG_ERR, "Bogus umask value %s", argv[2]);
		return PAM_SESSION_ERR;
	}
   }

   if (argc >= 4) {
	if (strlen(argv[3]) >= sizeof(skeldir)) {
		pam_syslog(NULL, LOG_ERR, "Too long skeldir path.");
		return PAM_SESSION_ERR;
	}
	strcpy(skeldir, argv[3]);
   }

   /* Stat the home directory, if something exists then we assume it is
      correct and return a success */
   if (stat(pwd->pw_dir, &st) == 0)
	return PAM_SUCCESS;

   if (make_parent_dirs(pwd->pw_dir, 0) != PAM_SUCCESS)
	return PAM_PERM_DENIED;

   return create_homedir(pwd, skeldir, pwd->pw_dir);
}
