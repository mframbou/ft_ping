/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   get_next_line.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/19 10:19:48 by mframbou          #+#    #+#             */
/*   Updated: 22-02-2022 16:07 by                                             */
/*                                                                            */
/* ************************************************************************** */

#include <unistd.h>
#include <stdlib.h>

#ifndef BUFFER_SIZE
# define BUFFER_SIZE 32
#endif

char	*gnl_ft_strdup(char *str);
int		*gnl_should_flush(void);
void	flush_buffer(char *buffer, int size);

// Concatenate 2 strings and puts the result in a new string
// Then frees the original string (if it's null, it doesn't do it, source: man)
static char	*ft_strcatdup(char *str1, char *str2, int str2len)
{
	int		i;
	int		j;
	char	*res;

	if (!str1 || !str2)
		return (NULL);
	i = 0;
	while (str1[i])
		i++;
	res = malloc(sizeof(char) * (i + str2len + 1));
	if (res)
	{
		j = str2len;
		res[i + j] = '\0';
		while (--j >= 0)
			res[i + j] = str2[j];
		while (--i >= 0)
			res[i] = str1[i];
	}
	free(str1);
	return (res);
}

static char	has_newline(char *str)
{
	while (*str)
		if (*str++ == '\n')
			return (1);
	return (0);
}

static char	*get_first_line_in_string_free(char *str)
{
	int		i;
	char	*res;

	if (!str)
		return (NULL);
	i = 0;
	while (str[i] != '\n' && str[i])
		i++;
	if (str[i] == '\n')
		i++;
	res = malloc (sizeof (char) * (i + 1));
	res[i--] = '\0';
	while (i >= 0)
	{
		res[i] = str[i];
		i--;
	}
	free(str);
	return (res);
}

static void	shift_buffer(char *buffer)
{
	int	i;
	int	j;

	i = 0;
	j = 0;
	while (buffer[i] != '\n' && buffer[i])
		i++;
	if (buffer[i] == '\n')
	{
		i++;
		while (buffer[i])
			buffer[j++] = buffer[i++];
		while (buffer[j])
			buffer[j++] = '\0';
	}
	else
	{
		while (buffer[j])
			buffer[j++] = '\0';
	}
}

// Copy the content of the buffer (if any)
// Loop until newline
// Get only the result before \n
// Shift the buffer to remove the first line
// Return the result
char	*get_next_line(int fd)
{
	char		*result;
	static char	buffer[BUFFER_SIZE];
	int			head_pos;
	int			i;

	if (*gnl_should_flush())
		flush_buffer(buffer, BUFFER_SIZE);
	head_pos = 1;
	result = gnl_ft_strdup(buffer);
	while (head_pos > 0 && !has_newline(result))
	{
		head_pos = read(fd, buffer, BUFFER_SIZE);
		i = head_pos;
		while (i < BUFFER_SIZE)
			buffer[i++] = '\0';
		result = ft_strcatdup(result, buffer, head_pos);
	}
	result = get_first_line_in_string_free(result);
	if (*result == '\0' || head_pos == -1)
	{
		free(result);
		return (NULL);
	}
	shift_buffer(buffer);
	return (result);
}
