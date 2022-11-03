/* ************************************************************************** */
/*                       .-.                       .                          */
/*                      / -'                      /                           */
/*       .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (               */
/*        )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )         .    */
/*   By: '/   /   (`.'  /      `-'-.-/   /.- (.''--'`-`-'  `--':        /     */
/*                  -'            (   \  / .-._.).--..-._..  .-.  .-../ .-.   */
/*   Created: 27-01-2022  by       `-' \/ (   )/    (   )  )/   )(   / (  |   */
/*   Updated: 27-01-2022 11:15 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                 `._;  `._;                   `-            */
/* ************************************************************************** */

#include "../libft.h"
#include <stdlib.h>

/*
	Removes a substring between start and end from str
	start at 'index' for 'size' bytes
*/
char	*ft_rm_substr(char *src, size_t index, size_t size)
{
	char	*res;
	int		new_len;

	if (index > ft_strlen(src) - 1 || index + size > ft_strlen(src))
		return (NULL);
	new_len = ft_strlen(src) - (size);
	res = malloc(sizeof(char) * (new_len + 1));
	if (res)
	{
		ft_bzero(res, new_len + 1);
		ft_strlcat(res, src, index + 1);
		ft_strlcat(res, &(src[index + size]), new_len + 1);
	}
	return (res);
}
