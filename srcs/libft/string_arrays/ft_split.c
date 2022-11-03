/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/06 17:15:28 by mframbou          #+#    #+#             */
/*   Updated: 22-02-2022 14:41 by                                             */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "../libft.h"

static int	is_in_set(char c, char *arr)
{
	while (*arr)
		if (*(arr++) == c)
			return (1);
	return (0);
}

static void	*clean_array(char **arr)
{
	int	i;

	i = 0;
	while (arr[i])
		free(arr[i++]);
	return (NULL);
}

static int	get_substring_count(char const *str, char *charset)
{
	int		str_count;
	size_t	i;

	str_count = 0;
	i = 0;
	while (str[i])
	{
		i++;
		while (!is_in_set(str[i], charset) && str[i] != '\0')
			i++;
		if (i != 0 && !is_in_set(str[i - 1], charset))
			str_count++;
	}
	return (str_count);
}

char	**ft_split(char const *s, char *charset)
{
	char	**res;
	int		substr_count;
	int		i;
	size_t	j;
	size_t	substr_start;

	i = -1;
	j = 0;
	substr_count = get_substring_count(s, charset);
	res = malloc(sizeof (char *) * (substr_count + 1));
	if (!res)
		return (NULL);
	while (++i < substr_count)
	{
		while (s[j] != '\0' && is_in_set(s[j], charset))
			j++;
		substr_start = j;
		while (s[j] != '\0' && !is_in_set(s[j], charset))
			j++;
		res[i] = ft_substr(s, substr_start, (j - substr_start));
		if (!res[i])
			return (clean_array(res));
	}
	res[i] = 0;
	return (res);
}
