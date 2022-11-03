/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_calloc.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/08 15:14:29 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 15:11 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "../libft.h"

static void	*ft_memalloc(size_t size)
{
	char	*res;
	size_t	i;

	res = (char *) malloc(size);
	if (res)
	{
		i = 0;
		while (i < size)
		{
			res[i] = 0;
			i++;
		}
	}
	return ((void *) res);
}

// If one of 2 args == 0, then just return malloc(0)
// Returning NULL didn't passed the hardcore test, so return
// the other possible value (source: man)
void	*ft_calloc(size_t nmemb, size_t size)
{
	return (ft_memalloc(nmemb * size));
}
