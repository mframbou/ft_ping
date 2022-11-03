/* ************************************************************************** */
/*                       .-.                       .                          */
/*                      / -'                      /                           */
/*       .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (               */
/*        )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )         .    */
/*   By: '/   /   (`.'  /      `-'-.-/   /.- (.''--'`-`-'  `--':        /     */
/*                  -'            (   \  / .-._.).--..-._..  .-.  .-../ .-.   */
/*   Created: 27-01-2022  by       `-' \/ (   )/    (   )  )/   )(   / (  |   */
/*   Updated: 27-01-2022 12:28 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                 `._;  `._;                   `-            */
/* ************************************************************************** */

#include "../libft.h"

/*
	Checks if the given string is a valid number
	(eg. "---+" in invalid, even though atoi would count it as 0)
*/
int	ft_is_valid_nbr(char *nbr_str)
{
	int	i;

	i = 0;
	while (nbr_str[i] && (nbr_str[i] == '-' || nbr_str[i] == '+'))
		i++;
	if (!nbr_str[i] || !ft_isdigit(nbr_str[i]))
		return (0);
	while (nbr_str[i] && ft_isdigit(nbr_str[i]))
		i++;
	if (nbr_str[i])
		return (0);
	return (1);
}
