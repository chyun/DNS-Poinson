/* our fabrication table entry struct, holds the rule table for spoofing */
struct ft_entry {
    char name[128];                     /* dns name to look for */
};

struct ft_entry *ftable;                /* fabrication table */

int num_entries = 0;                    /* number of entries read into ftable */