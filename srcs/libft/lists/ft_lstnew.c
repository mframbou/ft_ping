/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_lstnew.c                                        :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42nice.fr>      +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/08/07 21:53:23 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 15:11 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include <stdlib.h>
#include "../libft.h"

t_list	*ft_lstnew(void const *content)
{
	t_list	*link;

	link = (t_list *) malloc(sizeof (t_list));
	if (link)
	{
		link->content = (void *) content;
		link->next = NULL;
	}
	return (link);
}

/*
t_list	*ft_lstnew(void const *content, size_t content_size)
{
	t_list	*link;

	link = (t_list *) malloc(sizeof (t_list));
	if (!link)
		return (NULL);
	if (content)
	{
		link->content = malloc(content_size);
		if (!link->content)
		{
			free(link);
			return (NULL);
		}
		ft_memcpy(link->content, content, content_size);
	}
	else
	{
		link->content = NULL;
		content_size = 0;
	}
	link->content_size = content_size;
	link->next = NULL;
	return (link);
}
*/