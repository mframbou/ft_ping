/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line_utils.c                              :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/19 12:56:57 by mframbou          #+#    #+#             */
/*   Updated: 22-02-2022 16:05 by                                             */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
char	*get_next_line(int fd);

char	*gnl_ft_strdup(char *str)
{
	int		i;
	char	*res;

	i = 0;
	while (str[i])
		i++;
	res = malloc (sizeof (char) * (i + 1));
	res[i] = '\0';
	while (--i >= 0)
		res[i] = str[i];
	return (res);
}

/*
	If we open a file, read but not to the end, close it, the buffer in gnl is
	still present. Now if we reopen the file, the buffer will be appened to
	out read value, which will cause some weird behavior since we have
	no idea that file was closed and reopened in gnl and have no way to know it
*/
int	*gnl_should_flush(void)
{
	static int	should_flush = 0;

	return (&should_flush);
}

void	flush_gnl_buffer(void)
{
	*gnl_should_flush() = 1;
}

void	flush_buffer(char *buffer, int size)
{
	int	i;

	i = 0;
	while (i < size)
		buffer[i++] = '\0';
	*gnl_should_flush() = 0;
}