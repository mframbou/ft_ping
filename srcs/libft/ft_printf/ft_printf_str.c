/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_str.c                                    :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 13:17:42 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 14:54 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf_local.h"

int	ft_printf_str(va_list *args, int fd)
{
	char	*str;

	str = va_arg(*args, char *);
	if (str)
	{
		ft_printf_putstr_fd(str, fd);
		return (ft_printf_strlen(str));
	}	
	else
	{
		ft_printf_putstr_fd("(null)", fd);
		return (ft_printf_strlen("(null)"));
	}
}
