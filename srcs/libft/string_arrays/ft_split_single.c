/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split_single.c                                  :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/06 17:15:28 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 15:11 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "../libft.h"

static void	*clean_array(char **arr)
{
	int	i;

	i = 0;
	while (arr[i])
		free(arr[i++]);
	return (NULL);
}

/*
	There is ALWAYS at least 1 string (get_count("") = 1)
*/
static int	get_substring_count(char const *str, char c)
{
	int		str_count;
	size_t	i;

	str_count = 1;
	i = 0;
	while (str[i])
	{
		while (str[i] != c && str[i] != '\0')
			i++;
		if (str[i] == c && str[i] != '\0')
		{
			str_count++;
			i++;
		}
	}
	return (str_count);
}

/*
	Splits everything between single char, eg. :

	- FT_Split("Salut,,c'est un test,,, on vera bien", ',')
		=> ["Salut", "c'est un test", " on verra bien"]

	- FT_Split_single("Salut,,c'est un test,,, on vera bien", ',')
		=> ["Salut", "", "c'est un test", "", "", " on verra bien"]
*/
char	**ft_split_single(char const *s, char c)
{
	char	**res;
	int		substr_count;
	int		i;
	size_t	j;
	size_t	substr_start;

	i = -1;
	j = 0;
	substr_count = get_substring_count(s, c);
	res = malloc(sizeof (char *) * (substr_count + 1));
	if (!res)
		return (NULL);
	while (++i < substr_count)
	{
		substr_start = j;
		while (s[j] != c && s[j] != '\0')
			j++;
		res[i] = ft_substr(s, substr_start, (j - substr_start));
		if (!res[i])
			return ((char **) clean_array(res));
		if (s[j])
			j++;
	}
	res[i] = 0;
	return (res);
}
