/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memmove.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42nice.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/01 22:41:53 by mframbou          #+#    #+#             */
/*   Updated: 2021/08/05 19:40:22 by mframbou         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

/*
[---dst---]
  [---src---] ==> Copy fromm the start of src to start of dst
 

    [---dst---] ==> Copy from the end of src to the end of dst
[---src---]
*/

#include <string.h>

void	*ft_memmove(void *dest, const void *src, size_t n)
{
	size_t	i;
	char	*char_dest;
	char	*char_src;

	char_dest = (char *) dest;
	char_src = (char *) src;
	if (dest == NULL && src == NULL)
		return (NULL);
	if (char_dest < char_src)
	{
		i = 0;
		while (i < n)
		{
			char_dest[i] = char_src[i];
			i++;
		}
		return (dest);
	}
	else
	{
		i = n;
		while (i-- > 0)
			char_dest[i] = char_src[i];
		return (dest);
	}
}
