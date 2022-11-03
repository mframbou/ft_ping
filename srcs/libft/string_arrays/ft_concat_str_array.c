/* ************************************************************************** */
/*                       .-.                       .                          */
/*                      / -'                      /                           */
/*       .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (               */
/*        )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )         .    */
/*   By: '/   /   (`.'  /      `-'-.-/   /.- (.''--'`-`-'  `--':        /     */
/*                  -'            (   \  / .-._.).--..-._..  .-.  .-../ .-.   */
/*   Created: 27-01-2022  by       `-' \/ (   )/    (   )  )/   )(   / (  |   */
/*   Updated: 27-01-2022 11:28 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                 `._;  `._;                   `-            */
/* ************************************************************************** */

#include "../libft.h"
#include <stdlib.h>

/*
	Converts a string array to one line containing all strings separated by
	one space
*/
char	*ft_concat_str_array(char **array)
{
	int		i;
	int		j;
	int		k;
	char	*res;

	k = 0;
	i = 0;
	while (array[i])
		k += ft_strlen(array[i++]) + 1;
	res = malloc(sizeof(char) * (k));
	if (res)
	{
		i = -1;
		j = 0;
		while (array[++i])
		{
			k = 0;
			while (array[i][k])
				res[j++] = array[i][k++];
			if (array[i + 1])
				res[j++] = ' ';
		}
		res[j] = '\0';
	}
	return (res);
}
