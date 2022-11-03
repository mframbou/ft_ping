/* ************************************************************************** */
/*                       .-.                       .                          */
/*                      / -'                      /                           */
/*       .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (               */
/*        )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )         .    */
/*   By: '/   /   (`.'  /      `-'-.-/   /.- (.''--'`-`-'  `--':        /     */
/*                  -'            (   \  / .-._.).--..-._..  .-.  .-../ .-.   */
/*   Created: 27-01-2022  by       `-' \/ (   )/    (   )  )/   )(   / (  |   */
/*   Updated: 27-01-2022 11:14 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                 `._;  `._;                   `-            */
/* ************************************************************************** */

#include "../libft.h"
#include <stdlib.h>

/*
	Removes a char from a string
*/
char	*ft_rm_char(char *src, size_t index)
{
	char	*res;
	int		new_len;

	if (index > ft_strlen(src) - 1)
		return (NULL);
	new_len = ft_strlen(src) - 1;
	res = malloc(sizeof(char) * (new_len + 1));
	if (res)
	{
		ft_bzero(res, new_len + 1);
		ft_strlcat(res, src, index + 1);
		ft_strlcat(res, &(src[index + 1]), new_len + 1);
	}
	return (res);
}
