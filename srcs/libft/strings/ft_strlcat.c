/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strlcat.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42nice.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/03 19:48:03 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 15:10 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include <string.h>
#include "../libft.h"

// If the dest is more bytes than n, it will be considered as n bytes long
// So if it wasn't null terminated, it will not be in the result
// strlcat("Hey", "This is a test", 2) => Traverse 2 bytes, don't find
// terminating char, assume that dest is 2 bytes long, then return 2 + len(src)
size_t	ft_strlcat(char *dest, const char *src, size_t n)
{
	size_t	src_len;
	size_t	dst_len;
	size_t	i;
	size_t	j;

	src_len = ft_strlen(src);
	i = 0;
	while (dest[i] != '\0' && i < n)
		i++;
	if (i == n)
		return (n + src_len);
	dst_len = i;
	j = 0;
	while (src[j] != '\0' && i < n - 1)
	{
		dest[i] = src[j];
		i++;
		j++;
	}
	dest[i] = '\0';
	return (dst_len + src_len);
}
