/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_memchr.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42nice.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/03 16:50:30 by mframbou          #+#    #+#             */
/*   Updated: 2021/08/05 18:49:17 by mframbou         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>

void	*ft_memchr(const void *s, int c, size_t n)
{
	unsigned char	*uchar_src;
	size_t			i;

	uchar_src = (unsigned char *) s;
	i = 0;
	while (i < n)
	{
		if (uchar_src[i] == (unsigned char) c)
			return (&(uchar_src[i]));
		i++;
	}
	return (NULL);
}
