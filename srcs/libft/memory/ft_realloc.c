/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_realloc.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/12/17 17:47:31 by mframbou          #+#    #+#             */
/*   Updated: 22-02-2022 14:09 by                                             */
/*                                                                            */
/* ************************************************************************** */

#include "../libft.h"
#include <stdlib.h>

void	*ft_realloc(void *mem, size_t size, size_t new_size)
{
	void	*res;
	size_t	i;

	res = malloc(new_size);
	i = 0;
	while (i < size)
	{
		((char *)res)[i] = ((char *)mem)[i];
		i++;
	}
	return (res);
}
