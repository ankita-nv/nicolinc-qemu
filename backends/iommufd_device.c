/*
 * QEMU abstract of Host IOMMU
 *
 * Copyright (C) 2024 Intel Corporation.
 *
 * Authors: Yi Liu <yi.l.liu@intel.com>
 *          Zhenzhong Duan <zhenzhong.duan@intel.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <sys/ioctl.h>
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "sysemu/iommufd_device.h"
#include "trace.h"

int iommufd_device_attach_hwpt(IOMMUFDDevice *idev, uint32_t hwpt_id)
{
    g_assert(idev->ops->attach_hwpt);
    return idev->ops->attach_hwpt(idev, hwpt_id);
}

int iommufd_device_detach_hwpt(IOMMUFDDevice *idev)
{
    g_assert(idev->ops->detach_hwpt);
    return idev->ops->detach_hwpt(idev);
}

int iommufd_device_get_info(IOMMUFDDevice *idev,
                            enum iommu_hw_info_type *type,
                            uint32_t len, void *data)
{
    struct iommu_hw_info info = {
        .size = sizeof(info),
        .flags = 0,
        .dev_id = idev->dev_id,
        .data_len = len,
        .data_uptr = (uintptr_t)data,
    };
    int ret;

    ret = ioctl(idev->iommufd->fd, IOMMU_GET_HW_INFO, &info);
    if (ret) {
        error_report("Failed to get info %m");
    } else {
        *type = info.out_data_type;
    }

    return ret;
}

int iommufd_device_invalidate_cache(IOMMUFDDevice *idev,
                                    uint32_t data_type, uint32_t entry_len,
                                    uint32_t *entry_num, void *data_ptr)
{
    int ret, fd = idev->iommufd->fd;
    struct iommu_dev_invalidate cache = {
        .size = sizeof(cache),
        .dev_id = idev->dev_id,
        .data_type = data_type,
        .entry_len = entry_len,
        .data_uptr = (uint64_t)data_ptr,
    };

    cache.entry_num = *entry_num;
    ret = ioctl(fd, IOMMU_DEV_INVALIDATE, &cache);

    trace_iommufd_device_invalidate_cache(fd, idev->dev_id, data_type, entry_len,
                                          *entry_num, cache.entry_num,
                                          (uint64_t)data_ptr, ret);
    if (ret) {
        ret = -errno;
        error_report("IOMMU_DEV_INVALIDATE failed: %s", strerror(errno));
    } else {
        *entry_num = cache.entry_num;
    }

    return ret;
}

struct IOMMUFDViommu *iommufd_device_alloc_viommu(IOMMUFDDevice *idev,
                                                  uint32_t hwpt_id)
{
    int ret, fd = idev->iommufd->fd;
    struct IOMMUFDViommu *viommu = g_malloc(sizeof(*viommu));
    struct iommu_viommu_alloc alloc_viommu = {
        .size = sizeof(alloc_viommu),
        .dev_id = idev->dev_id,
        .hwpt_id = hwpt_id,
    };

    if (!viommu) {
        error_report("failed to allocate viommu object");
        return NULL;
    }

    ret = ioctl(fd, IOMMU_VIOMMU_ALLOC, &alloc_viommu);

    trace_iommufd_device_alloc_viommu(fd, idev->dev_id, hwpt_id,
                                      alloc_viommu.out_viommu_id, ret);
    if (ret) {
        error_report("IOMMU_VIOMMU_ALLOC failed: %s", strerror(errno));
        g_free(viommu);
        return NULL;
    }

    viommu->viommu_id = alloc_viommu.out_viommu_id;
    viommu->s2_hwpt_id = hwpt_id;
    viommu->iommufd = idev->iommufd;
    return viommu;
}

int iommufd_viommu_set_data(IOMMUFDViommu *viommu,
                            uint32_t data_type, uint32_t len, void *data_ptr)
{
    int ret, fd = viommu->iommufd->fd;
    struct iommu_viommu_set_data viommu_set_data = {
        .size = sizeof(viommu_set_data),
        .flags = 0,
        .viommu_id = viommu->viommu_id,
        .data_type = data_type,
        .data_len = len,
        .data_uptr = (uint64_t)data_ptr,
    };

    ret = ioctl(fd, IOMMU_VIOMMU_SET_DATA, &viommu_set_data);

    trace_iommufd_viommu_set_data(fd, viommu->viommu_id, data_type,
                                  len, (uint64_t)data_ptr, ret);
    if (ret) {
        ret = -errno;
        error_report("IOMMU_VIOMMU_SET_DATA failed: %s", strerror(errno));
    }
    return ret;
}

int iommufd_device_set_virtual_id(IOMMUFDDevice *idev, IOMMUFDViommu *viommu,
                                  uint32_t id_type, uint64_t id)
{
    int ret, fd = idev->iommufd->fd;
    struct iommu_dev_set_virtual_id set_id = {
        .size = sizeof(set_id),
        .dev_id = idev->dev_id,
        .viommu_id = viommu->viommu_id,
        .id_type = id_type,
        .id = id,
    };

    ret = ioctl(fd, IOMMU_DEV_SET_VIRTUAL_ID, &set_id);

    trace_iommufd_device_set_virtual_id(fd, idev->dev_id, viommu->viommu_id,
                                        id_type, id, ret);
    if (ret) {
        error_report("Failed to set virtual id %d", ret);
    }

    return ret;
}

void *iommufd_viommu_get_shared_page(int iommufd, uint32_t viommu_id,
                                     uint32_t size, bool readonly)
{
    uintptr_t pgsize = qemu_real_host_page_size();
    off_t offset = viommu_id * pgsize;
    int prot = PROT_READ;
    void *page;

    if (!viommu_id) {
        error_report("failed to get shared page with a NULL viommu_id");
        return NULL;
    }
    if (!readonly) {
        prot |= PROT_WRITE;
    }

    page = mmap(NULL, size, prot, MAP_SHARED, iommufd, offset);
    if (page == MAP_FAILED) {
        error_report("failed to get shared page (size=0x%x) for viommu (id=%d)",
                     size, viommu_id);
        return NULL;
    }

    trace_iommufd_viommu_get_shared_page(iommufd, viommu_id, size, readonly);

    return page;
}

void iommufd_viommu_put_shared_page(int iommufd, uint32_t viommu_id,
                                    void *page, uint32_t size)
{
    munmap(page, size);
}

void iommufd_device_init(void *_idev, size_t instance_size,
                         IOMMUFDBackend *iommufd, uint32_t dev_id,
                         uint32_t ioas_id, IOMMUFDDeviceOps *ops)
{
    IOMMUFDDevice *idev = (IOMMUFDDevice *)_idev;

    g_assert(sizeof(IOMMUFDDevice) <= instance_size);

    idev->iommufd = iommufd;
    idev->dev_id = dev_id;
    idev->ioas_id = ioas_id;
    idev->ops = ops;
}
