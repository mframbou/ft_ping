/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_strtrim.c                                       :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42nice.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/06 16:50:36 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 15:11 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "../libft.h"

static int	ft_isinset(char c, char const *set)
{
	while (*set)
	{
		if (*set++ == c)
			return (1);
	}
	return (0);
}

// " T "
//   ^
// start & end on char T (=> size 0 => wrong)
// ==> So always check for character before end "cursor" to get the right size
// "    "
//  ^  ^
// END START
// (Also handle case where string if full of whitespaces)
char	*ft_strtrim(char const *s, char const *set)
{
	size_t	start;
	size_t	end;
	char	*res;

	start = 0;
	end = 0;
	while (ft_isinset(s[start], set))
		start++;
	while (s[end])
		end++;
	while (ft_isinset(s[end - 1], set) && end != 0 && end > start)
		end--;
	res = (char *) malloc(sizeof(char) * (end - start + 1));
	if (res)
	{
		res[end - start] = '\0';
		while (end-- > start)
			res[end - start] = s[end];
	}
	return (res);
}
