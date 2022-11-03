/* ************************************************************************** */
/*                                                                            */
/*                                  .-.                       .               */
/*                                 / -'                      /                */
/*                  .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (    */
/*   By:             )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )   */
/*                  '/   /   (`.'  /      `-'-''/   /   (.'`--'`-`-'  `--':   */
/*   Created: 26-01-2022  by  `-'                        `-'                  */
/*   Updated: 26-01-2022 15:32 by                                             */
/*                                                                            */
/* ************************************************************************** */

#ifndef FT_PRINTF_LOCAL_H
# define FT_PRINTF_LOCAL_H

# include <stdlib.h>
# include <unistd.h>
# include <stdarg.h>
# ifdef __linux__
#  include <stdint.h>
# endif

typedef struct s_conversions
{
	char	type;
	int		(*print_data)(va_list *, int);
}	t_conversions;

int		ft_printf_char(va_list *args, int fd);
int		ft_printf_hex_min(va_list *args, int fd);
int		ft_printf_hex_maj(va_list *args, int fd);
int		ft_printf_integer(va_list *args, int fd);
int		ft_printf_percent(va_list *args, int fd);
int		ft_printf_pointer(va_list *args, int fd);
int		ft_printf_str(va_list *args, int fd);
int		ft_printf_unsigned_int(va_list *args, int fd);

void	ft_printf_putchar_fd(char c, int fd);
void	ft_printf_putstr_fd(char const *s, int fd);
char	*ft_printf_strdup(const char *s);
size_t	ft_printf_strlen(const char *s);

#endif