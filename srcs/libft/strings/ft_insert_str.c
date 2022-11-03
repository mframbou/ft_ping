/* ************************************************************************** */
/*                       .-.                       .                          */
/*                      / -'                      /                           */
/*       .  .-. .-.   -/--).--..-.  .  .-. .-.   /-.  .-._.)  (               */
/*        )/   )   )  /  /    (  |   )/   )   ) /   )(   )(    )         .    */
/*   By: '/   /   (`.'  /      `-'-.-/   /.- (.''--'`-`-'  `--':        /     */
/*                  -'            (   \  / .-._.).--..-._..  .-.  .-../ .-.   */
/*   Created: 27-01-2022  by       `-' \/ (   )/    (   )  )/   )(   / (  |   */
/*   Updated: 27-01-2022 11:29 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                 `._;  `._;                   `-            */
/* ************************************************************************** */

#include "../libft.h"
#include <stdlib.h>

/*
	Insert 'str' in 'src' at index
	("Salut bg", "gros", 4) => "Salutgros bg"
*/
char	*ft_insert_str(char *src, char *str, size_t index)
{
	char	*res;
	size_t	i;
	size_t	j;
	size_t	k;

	if (index > ft_strlen(src))
		return (NULL);
	res = malloc(sizeof(char) * (ft_strlen(src) + ft_strlen(str) + 1));
	if (res)
	{
		i = 0;
		j = 0;
		k = 0;
		while (src[j] && j < index)
			res[i++] = src[j++];
		while (str[k])
			res[i++] = str[k++];
		while (src[j])
			res[i++] = src[j++];
		res[i] = '\0';
	}
	return (res);
}
