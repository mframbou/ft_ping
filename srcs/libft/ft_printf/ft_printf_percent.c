/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_printf_percent.c                                :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: mframbou <mframbou@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/10/22 13:38:24 by mframbou          #+#    #+#             */
/*   Updated: 26-01-2022 14:54 by      /\  `-'/      `-'  '/   (  `-'-..`-'-' */
/*                                                                            */
/* ************************************************************************** */

#include "ft_printf_local.h"

int	ft_printf_percent(va_list *args, int fd)
{
	(void) args;
	ft_printf_putchar_fd('%', fd);
	return (1);
}
