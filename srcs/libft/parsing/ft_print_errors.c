/* ************************************************************************** */
/*                                                                            */
/*                                  .-.                       .               */
/*                                 / -'                      /                */
/*                  .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (    */
/*   By:             )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )   */
/*                  '/   /   (`.'  /      `-'-''/   /   (.'`--'`-`-'  `--':   */
/*   Created: 22-02-2022  by  `-'                        `-'                  */
/*   Updated: 22-02-2022 14:11 by                                             */
/*                                                                            */
/* ************************************************************************** */

#include "../libft.h"
#include <unistd.h>

/*
	Always return -1
*/
int	print_error_plus_arg(char *arg)
{
	write(1, "Error\n", 7);
	write(1, arg, ft_strlen(arg));
	return (-1);
}

/*
	Always return -1
*/
int	print_error(char *error)
{
	write(1, error, ft_strlen(error));
	return (-1);
}

/*
	Print
	[(Error\n)]
	[Error msg]

	Print the error only if the arg != 0
	So that we can print multiple errors
	Error
	err1
	err2
	err3

	instead of
	Error
	err1
	Error
	err2
	Error
	err3

	Also set the argument to 1 since we printed error
*/
void	print_error_if_needed(char *error, int *printed_error)
{
	if (!printed_error)
	{
		write(1, "Error\n", 6);
		*printed_error = 1;
	}
	print_error(error);
}