/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strdup.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42nice.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/03 17:05:07 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 15:11 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "../libft.h"

char	*ft_strdup(const char *s)
{
	const char	*str;
	char		*res;
	int			size;

	size = 0;
	str = s;
	while (*str++)
		size++;
	str = s;
	res = (char *) malloc(sizeof (char) * (size + 1));
	if (res == NULL)
		return (NULL);
	while (size >= 0)
	{
		res[size] = str[size];
		size--;
	}
	return (res);
}
