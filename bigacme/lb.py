"""Functions that interacts with the loadbalancer"""
import logging
import bigsuds

logger = logging.getLogger(__name__)

# suds is very noisy
logging.getLogger('suds.client').setLevel(logging.CRITICAL)

class LoadBalancerError(Exception):
    """Superclass for all load balancer exceptions."""
    pass
class NoActiveLoadBalancersError(LoadBalancerError):
    """Raised when none of the specified load balancers reports as active"""
    pass
class PartitionNotFoundError(LoadBalancerError):
    """Raised when the partition was not found"""
    pass
class CSRNotFoundError(LoadBalancerError):
    """Raised when the CSR was not found on the device"""
    pass
class AccessDeniedError(LoadBalancerError):
    """Raised when the device denies access"""
    pass
class NotFoundError(LoadBalancerError):
    """Raised when the specified resource was not found on the load balander"""
    pass

def connect(config):
    """Connects to the Big-IP unit(s)"""
    lb1 = bigsuds.BIGIP(config.lb1, config.lb_user, config.lb_pwd,
                        verify=True)
    if config.lb2:
        lb2 = bigsuds.BIGIP(config.lb2, config.lb_user, config.lb_pwd,
                            verify=config.lb_verify)
        lb1status = lb1.System.Failover.get_failover_state()
        lb2status = lb2.System.Failover.get_failover_state()

        if lb1status == 'FAILOVER_STATE_ACTIVE':
            return lb1
        elif lb2status == 'FAILOVER_STATE_ACTIVE':
            return lb2
        else:
            raise NoActiveLoadBalancersError('None of the devices were active.')
    else:
        # Just to check the connection
        lb1.System.SystemInfo.get_uptime()
        return lb1

def send_challenge(bigip, domain, path, string, config):
    """Sends the challenge to the Big-IP"""
    shortpath = path.split('/')[-1]
    key = '%s:%s' % (domain, shortpath)
    logger.debug('Adding record %s with value %s to datagroup %s in partition %s', key, string,
                 config.lb_dg, config.lb_dg_partition)
    bigip.System.Session.set_active_folder('/%s' % config.lb_dg_partition)
    datagroup = bigip.LocalLB.Class
    class_members = [{'name': config.lb_dg, 'members': [key]}]
    try:
        datagroup.add_string_class_member(class_members)
    except bigsuds.ServerError as error:
        if 'The requested class string item (/%s/%s %s) already exists in partition' % (
                config.lb_dg_partition, config.lb_dg, key) in error.message:
            logger.debug('The record already exist. Deleting it before adding it again')
            remove_challenge(bigip, domain, path, config)
            datagroup.add_string_class_member(class_members)
        else:
            raise
    datagroup.set_string_class_member_data_value(class_members, [[string]])

def remove_challenge(bigip, domain, path, config):
    """Removes a record from a string Data Group"""
    shortpath = path.split('/')[-1]
    key = '%s:%s' % (domain, shortpath)
    logger.debug('Removing record %s from datagroup %s in partition %s', key, config.lb_dg,
                 config.lb_dg_partition)
    bigip.System.Session.set_active_folder('/%s' % config.lb_dg_partition)
    datagroup = bigip.LocalLB.Class
    class_members = [{'name': config.lb_dg, 'members': [key]}]
    datagroup.delete_string_class_member(class_members)

def get_csr(bigip, partition, csrname):
    """Downloads the specified csr from the loadbalancer"""
    try:
        bigip.System.Session.set_active_folder('/%s' % partition)
    except bigsuds.ServerError as error:
        if 'folder not found' in error.message:
            raise PartitionNotFoundError()
        else:
            raise
    try:
        pem_csr = bigip.Management.KeyCertificate.certificate_request_export_to_pem(
            'MANAGEMENT_MODE_DEFAULT', [csrname])[0]
    except bigsuds.ServerError as error:
        if 'Access Denied:' in error.message:
            raise AccessDeniedError()
        elif 'Not Found' in error.message:
            raise NotFoundError()
        else:
            raise
    return pem_csr

def upload_certificate(bigip, partition, name, certificates, overwrite=True):
    """Uploads a new certificate to the Big-IP"""
    try:
        bigip.System.Session.set_active_folder('/%s' % partition)
    except bigsuds.ServerError as error:
        if 'folder not found' in error.message:
            raise PartitionNotFoundError()
        elif 'Access Denied:' in error.message:
            raise AccessDeniedError()
        else:
            raise
    try:
        bigip.Management.KeyCertificate.certificate_import_from_pem('MANAGEMENT_MODE_DEFAULT',
                                                                    [name],
                                                                    [certificates],
                                                                    overwrite)
    except bigsuds.ServerError as error:
        if 'Access Denied:' in error.message:
            raise AccessDeniedError()
        else:
            raise
